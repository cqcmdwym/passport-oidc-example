var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var passport = require('passport');
var OidcStrategy = require('passport-openidconnect').Strategy;

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'MyVoiceIsMyPassportVerifyMe',
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use('oidc', new OidcStrategy({
  issuer: 'https://dev-334677.oktapreview.com/oauth2/default',
  authorizationURL: 'https://dev-334677.oktapreview.com/oauth2/default/v1/authorize',
  tokenURL: 'https://dev-334677.oktapreview.com/oauth2/default/v1/token',
  userInfoURL: 'https://dev-334677.oktapreview.com/oauth2/default/v1/userinfo',
  clientID: '0oahh9dj77H8nq03V0h7',
  clientSecret: '59ro2vUBgQ5mElcriDNnZTYezyjUYsMSmdwskUoS',
  callbackURL: 'http://localhost:3000/authorization-code/callback',
  scope: 'openid profile'
}, (issuer, sub, profile, accessToken, refreshToken, done) => {
  return done(null, profile);
}));

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

app.use('/login', passport.authenticate('oidc'));

app.use('/authorization-code/callback',
  passport.authenticate('oidc', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect('/');
  }
);

function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login')
}

app.use('/profile', ensureLoggedIn, (req, res) => {
  res.render('profile', { title: 'Express', user: req.user });
});


app.use('/', indexRouter);
app.use('/users', usersRouter);

app.get('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
