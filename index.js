require("dotenv").config(); // separete a credentical from code for security like client id, secrete code,cookie key
const express = require('express');  //for create server ,router,api 
const path = require('node:path'); // html file join
const https = require('node:https'); // for implementing https ecrypted req,and res
const fs = require('node:fs');   // for public folder
const passport = require('passport');  // is authentication and authorization middleware for express
const helmet = require('helmet');    // is middleware add security related headers in req and res
const cookiesSession = require('cookie-session') //for making client side cookies for store a data on browser
const Googlestrategy = require('passport-google-oauth20').Strategy;  // google strategy  for login with google and use oauth20 is security standard
const app = express();

const config = {
    clientID:process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:process.env.CALLBACK_URL,
}


app.use(cookiesSession({  
    name:'session',
    maxAge:1000*60*60*24,
    resave:false,
    saveUninitialized:true,
    keys:[process.env.COOKIE_KEY]
}));


app.use(function(request,response,next){
    if(request.session && !request.session.regenerate){
        request.session.regenerate = (cb)=>{
            cb();
        };
    }
    if(request.session && !request.session.save){
        request.session.save = (cb)=>{
            cb();
        };
    }
    next();
});

const verifyCallback = (accessToken,refreshToken,profile,done)=>{
console.log('Google profile',profile);
  return  done(null,profile) ;
}

passport.use(new Googlestrategy(config,verifyCallback));   

passport.serializeUser((user,done)=>{       //serializeUser - we save user's data into cookie
    console.log(user)
    done(null,user.id)       // null - for no error pass
});

passport.deserializeUser((Obj,done)=>{      //deserializeUser - we read user's data from the cookie
    done(null,Obj)
});

app.use(helmet())    ;  // secure express app  from small attack

app.use(passport.initialize());  // passport middleware intilize - for authentication

app.use(passport.session());


app.get('/auth/google',passport.authenticate('google',{scope:['profile']}));

app.get('/auth/google/callback',passport.authenticate('google',{
    failureRedirect:'/',
    successRedirect:'/secret',
    
}));

app.get('/auth/logout',(req,res)=>{});

app.get('/secret',(req,res)=>{
    res.send('Your secret value is 9100');
});

app.get('/',(req,res)=>{
    res.sendFile(path.join(__dirname, 'public','index.html'));
});


const server = https.createServer( {
    
    key:fs.readFileSync('key.pem'),
    cert:fs.readFileSync('cert.pem')
},app);

server.listen(3000,()=>{
    console.log('Server started at port 3000')
})