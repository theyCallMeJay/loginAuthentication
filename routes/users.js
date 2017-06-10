var express = require('express');
var router = express.Router();
var User = require('../models/user');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

/* GET users listing. */
router.get('/register', function(req, res, next) {
  res.render('register');
});


router.get('/login', function(req, res, next) {
  res.render('login');
});

//register user
router.post('/register', function(req, res, next) {
  var name = req.body.name;
  var email = req.body.email;
  var username = req.body.username;
  var password = req.body.password;
  var password2 = req.body.password2;

  //validation
  req.checkBody('name', 'Name is required').notEmpty();
  req.checkBody('email', 'email is required').notEmpty();
  req.checkBody('username', 'username is required').notEmpty();
  req.checkBody('password', 'password is required').notEmpty();
  req.checkBody('password2', 'passwords do not match').equals(req.body.password);


  var errors = req.validationErrors();

  if (errors) {
  	res.render('register', {
  		errors: errors
  	});
  }else{
  	var newUser = new User({
  		name: name,
  		email: email,
  		username: username,
  		password: password
  	});

  	User.createUser(newUser, function(err, user){
  		if (err) {
  			throw err;
  		}else{
  			console.log(user);
  		}
  	});

  	req.flash('success_msg', 'You are registered and can now login');
   	res.redirect('/users/login');
  }

});

passport.use(new LocalStrategy(
  function(username, password, done) {
  	User.getUserByUsername(username, function(err, user){
  		if (err) {throw err};
  		if (!user) {
  			return done(null, false, {message: 'unknown user'});
  		}

  		User.comparePassword(password, user.password, function(err, isMatch){
  			if (err) {throw err}
  			if (isMatch) {
  				return done(null, user);
  			}else{
  				return done(null, false, {message: 'Invalid password!'});	 	
  			}

  		});

  	});
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});


router.post('/login', passport.authenticate('local', {successRedirect: '/', failureRedirect: '/users/login', failureFlash:true}), function(req, res){
	res.redirect('/');
});

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});


module.exports = router;
