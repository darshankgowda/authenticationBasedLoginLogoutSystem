//jshint esversion:
import express from "express"
import bodyParser from "body-parser"
import ejs from "ejs"
import mongoose from "mongoose"
import Dotenv from "dotenv";
import session from "express-session"
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import findOrCreate from "mongoose-findorcreate"


const saltRounds = 10;
const app = express();
Dotenv.config();

app.use(bodyParser.urlencoded({
    extended:true
}));
app.use(express.static("public"));
app.set("view engine", "ejs"); // is used in a web application to tell the application to use the EJS (Embedded JavaScript) template engine for rendering web pages. 
app.use(session({
    secret: 'our little secret.',
    resave: false,
    saveUninitialized: true,
  }));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/userDB', {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String, 
    googleId: String
});
userSchema.plugin(passportLocalMongoose) //to hash and salt our passwords and save our users into mongoDB
userSchema.plugin(findOrCreate)

const User = new mongoose.model("user", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
})

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then(user => {
            done(null, user);
        })
        .catch(err => {
            done(err, null);
        });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'  //to avoid retrieve information form our google+ account and making to retrieve it only from userinfo which is one of there endpoint
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });  //if there in db just find, if not there create it
  }
));

app.get("/auth/google", passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/", (req, res) => {
    res.render("home.ejs");
})
app.get("/login", (req, res) => {
    res.render("login.ejs");
})
app.get("/register", (req, res) => {
    res.render("register.ejs");
})
app.get("/logout", (req, res) => {
    req.logOut((err) => {
        if (err) {
            console.log(err);
        }
        else {
            res.redirect("/");
        }
    });
})
app.get("/secrets", (req, res) => {   //isAuthenticated() is from passportjs
    if(req.isAuthenticated()) {  //to check whether the user is registered or not
        res.render("secrets") //because the person one who knew the /register has this page means he cab directly concatenate url with /register where the authentication is lost
    } else {
        res.redirect("/login")
    }
})  //this block is executed directly when the user is remembered by session
app.post("/register", (req, res) => {
    User.register({  //register() comes from passport-local-mongoose package
        username: req.body.username
    },
        req.body.password
    )
    .then(() => {  //Authentication is typically done at the time of login, not at the time of registration.
        passport.authenticate("local")(req, res, () => {   //this line is for password matching means before you should register first then this block is executed
            res.redirect("/secrets")
        })
    })  
    .catch((err) => {
        console.log(err);
        res.redirect("/register");  //returns back to /register page
    })
}) //register() method avoids creating new user, saving our user and intercating with mongoose directly
app.post("/login", (req, res) => {
    const user = new User({
        username:req.body.username, 
        password:req.body.password
    });
    req.login(user, (err) => {
        if(err) {
            console.log(err);
        }
        else {
            passport.authenticate("local")(req, res, () => {   //this line is for password matching means before you should register first then this block is executed
                res.redirect("/secrets")
            })
        }
    })
})
app.listen(3000, () => {
    console.log("listening to port 3000");
});

//when we restart the website the cookies got deleted
