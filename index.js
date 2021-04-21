const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const { body, validationResult } = require('express-validator');
const app = express();

var pages = require('./pages'); //*
var authHelper = require('./authHelper'); //*
var session = require('express-session');
app.use(express.static('static'));



app.use(express.urlencoded({extended:false}));
app.use(session(
    { 
      name: 'session',
      secret: 'dc5h-1t2uFb_DR6.OqOagybZa3kD5JM6_c',
      resave: false,
      saveUninitialized: false,
      maxAge:  60 * 60 * 1000
    }));

// SET OUR VIEWS AND VIEW ENGINE
app.set('views', path.join(__dirname,'views'));
app.set('view engine','ejs');

// APPLY COOKIE SESSION MIDDLEWARE
//app.use(cookieSession({
//    name: 'session',
//    keys: ['key1', 'key2'],
//    maxAge:  60 * 60 * 1000 // 1hr
//}));

// DECLARING CUSTOM MIDDLEWARE
const ifNotLoggedin = (req, res, next) => {
    if(!req.session.isLoggedIn){
        return res.render('login-register');
    }
    next();
}
const ifLoggedin = (req,res,next) => {
    if(req.session.isLoggedIn){
        return res.redirect('/home');
    }
    next();
}
// END OF CUSTOM MIDDLEWARE
// ROOT PAGE
app.get('/', ifNotLoggedin, (req,res,next) => {

    dbConnection.execute("SELECT `name` FROM `users` WHERE `id`=?",[req.session.userID])
    .then(([rows]) => {
        if(!req.session.email){
            Name = {name:rows[0].name}
        }
        else{
            Name = {name: req.session.email}
        }
        res.render('home',Name);
    });
    
});// END OF ROOT PAGE


// REGISTER PAGE
app.post('/register', ifLoggedin, 
// post data validation(using express-validator)
[
    body('user_email','Invalid email address!').isEmail().custom((value) => {
        return dbConnection.execute('SELECT `email` FROM `users` WHERE `email`=?', [value])
        .then(([rows]) => {
            if(rows.length > 0){
                return Promise.reject('This E-mail already in use!');
            }
            return true;
        });
    }),
    body('user_name','Username is Empty!').trim().not().isEmpty(),
    body('user_pass','The password must be of minimum length 6 characters').trim().isLength({ min: 6 }),
],// end of post data validation
(req,res,next) => {

    const validation_result = validationResult(req);
    const {user_name, user_pass, user_email} = req.body;
    // IF validation_result HAS NO ERROR
    if(validation_result.isEmpty()){
        // password encryption (using bcryptjs)
        bcrypt.hash(user_pass, 12).then((hash_pass) => {
            // INSERTING USER INTO DATABASE
            dbConnection.execute("INSERT INTO `users`(`name`,`email`,`password`) VALUES(?,?,?)",[user_name,user_email, hash_pass])
            .then(result => {
                res.send(`your account has been created successfully, Now you can <a href="/">Login</a>`);
            }).catch(err => {
                // THROW INSERTING USER ERROR'S
                if (err) throw err;
            });
        })
        .catch(err => {
            // THROW HASING ERROR'S
            if (err) throw err;
        })
    }
    else{
        // COLLECT ALL THE VALIDATION ERRORS
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING login-register PAGE WITH VALIDATION ERRORS
        res.render('login-register',{
            register_error:allErrors,
            old_data:req.body
        });
    }
});// END OF REGISTER PAGE


// LOGIN PAGE
app.post('/login', ifLoggedin, [
    body('user_email').custom((value) => {
        return dbConnection.execute('SELECT email FROM users WHERE email=?', [value])
        .then(([rows]) => {
            if(rows.length == 1){
                return true;
                
            }
            return Promise.reject('Invalid Email Address!');
            
        });
    }),
    body('user_pass','Password is empty!').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const {user_pass, user_email} = req.body;
    if(validation_result.isEmpty()){
        
        dbConnection.execute("SELECT * FROM `users` WHERE `email`=?",[user_email])
        .then(([rows]) => {
            bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                if(compare_result === true){
                    req.session.isLoggedIn = true;
                    req.session.userID = rows[0].id;

                    res.redirect('/');
                }
                else{
                    res.render('login-register',{
                        login_errors:['Invalid Password!']
                    });
                }
            })
            .catch(err => {
                if (err) throw err;
            });


        }).catch(err => {
            if (err) throw err;
        });
    }
    else{
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING login-register PAGE WITH LOGIN VALIDATION ERRORS
        res.render('login-register',{
            login_errors:allErrors
        });
    }
});
// END OF LOGIN PAGE

// Authorize //*
app.get('/authorize', function(req, res) { //*
    var authCode = req.query.code; //*
    if (authCode) { //*
      console.log(''); //*
      console.log('Retrieved auth code in /authorize: ' + authCode); //*
      authHelper.getTokenFromCode(authCode, tokenReceived, req, res); //*
    } //*
    else { //*
      // redirect to home //*
      console.log('/authorize called without a code parameter, redirecting to login'); //*
      res.redirect('/'); //*
    } //*
  }); //*
  //*
  function tokenReceived(req, res, error, token) { //*
    if (error) { //*
      console.log('ERROR getting token:'  + error); //*
      res.send('ERROR getting token: ' + error); //*
    } //*
    else { //*
      // save tokens in session //*
      req.session.access_token = token.token.access_token; //*
      req.session.refresh_token = token.token.refresh_token; //*
      req.session.email = authHelper.getEmailFromIdToken(token.token.id_token); //*
      req.session.isLoggedIn = true; //+
      req.session.userID = req.session.email; //+
      res.redirect('/'); //*
    } //*
  } //*
  //*
  app.get('/logincomplete', function(req, res) { //*
    var access_token = req.session.access_token; //*
    var refresh_token = req.session.access_token; //*
    var email = req.session.email; //*
    
    if (access_token === undefined || refresh_token === undefined) { //*
      console.log('/logincomplete called while not logged in'); //*
      res.redirect('/'); //*
      return; //*
    } //*
    //*
    res.send(pages.loginCompletePage(email)); //*
  }); //*
  
  app.get('/refreshtokens', function(req, res) { //*
    var refresh_token = req.session.refresh_token; //*
    if (refresh_token === undefined) { //*
      console.log('no refresh token in session'); //*
      res.redirect('/'); //*
    } //*
    else { //*
      authHelper.getTokenFromRefreshToken(refresh_token, tokenReceived, req, res); //*
    } //*
  }); //*
// End of Authorize

app.get('/mslogin', function(req, res) { //*
    res.send(pages.loginPage(authHelper.getAuthUrl())); //*
  }); //*

// LOGOUT
app.get('/logout',(req,res)=>{
    //session destroy
    //req.session = null;
    req.session.destroy()
    res.redirect('/');
});
// END OF LOGOUT

app.use('/', (req,res) => {
    res.status(404).send('<h1>404 Page Not Found!</h1>');
});



app.listen(3000, () => console.log("Server is Running..."));
