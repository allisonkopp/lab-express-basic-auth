const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcrypt');
const bcryptSalt = 10;

/* GET home page */
router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/signup', (req, res, next) => {
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const salt = bcrypt.genSaltSync(bcryptSalt);
  const hashPass = bcrypt.hashSync(password, salt);

  User.findOne({ username: username }).then(result => {
    if (username !== result) {
      res.render('auth/signup', {
        errorMessage: 'Username already exists. Try again.'
      });
    } else {
      User.create({
        username,
        password: hashPass
      })
        .then(_ => res.redirect('/'))
        .catch(error => console.log(error));
    }
  });
});

router.get('/login', (req, res, next) => {
  res.render('auth/login');
});

router.post('/login', (req, res, next) => {
  const theUsername = req.body.username;
  const thePassword = req.body.password;

  // $('#myPassword').strength({
  //   strengthClass: 'strength',
  //   strengthMeterClass: 'strength_meter',
  //   strengthButtonClass: 'button_strength',
  //   strengthButtonText: 'Show password',
  //   strengthButtonTextToggle: 'Hide Password'
  // });

  if (theUsername === '' || thePassword === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, username and password to sign up.'
    });
    return;
  }

  User.findOne({ username: theUsername })
    .then(user => {
      if (!user) {
        res.render('auth/login', {
          errorMessage: "The username doesn't exist."
        });
        return;
      }
      if (bcrypt.compareSync(thePassword, user.password)) {
        // Save the login in the session!
        req.session.currentUser = user;
        res.redirect('/main');
      } else {
        res.render('auth/login', {
          errorMessage: 'Incorrect password'
        });
      }
    })
    .catch(error => {
      next(error);
    });
});

router.get('/main', (req, res, next) => {
  res.render('auth/main');
});

// router.get('/private', (req, res, next) => {
//   res.render('auth/private');
// });

router.use((req, res, next) => {
  if (req.session.currentUser) {
    next();
  } else {
    res.redirect('/login');
  }
});
router.get('/private', (req, res, next) => {
  res.render('auth/private');
});

router.get('/logout', (req, res, next) => {
  req.session.destroy(err => {
    res.redirect('/login');
  });
});

module.exports = router;
