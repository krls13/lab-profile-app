const express = require("express");
const passport = require('passport');
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

// LOGIN

router.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, theUser, failureDetails) => {
    if (err) {
      res.status(500).json({ message: 'Something went wrong authenticating user' });
      return;
    }
    if (!theUser) {
      res.status(401).json(failureDetails);
      return;
    }
    req.login(theUser, (err) => {
      if (err) {
        res.status(500).json({ message: 'session save went bad.' });
        return;
      }
      res.status(200).json(theUser)
    })
  })(req, res, next)
});


router.post('/signup', (req, res, next) => {

  const { username, password } = req.body;

  console.log('username', username)
  console.log('password', password)

  // Check for non empty user or password
  if (!username || !password) {
    next(new Error('You must provide valid credentials'));
  }

  // Check if user exists in DB
  User.findOne({ username })
    .then(foundUser => {
      if (foundUser) throw new Error('Username already exists');

      const salt = bcrypt.genSaltSync(10);
      const hashPass = bcrypt.hashSync(password, salt);

      return new User({
        username,
        password: hashPass
      }).save();
    })
    // .then(savedUser => login(req, savedUser)) // Login the user using passport
    .then(user => res.json({ status: 'signup & login successfully', user })) // Answer JSON
    .catch(e => next(e));
});
router.get("/login", (req, res, next) => {
  res.render("auth/login", { "message": req.flash("error") });
});

// router.post("/login", passport.authenticate("local", {
//   successRedirect: "/",
//   failureRedirect: "/auth/login",
//   failureFlash: true,
//   passReqToCallback: true
// }));

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  if (username === "" || password === "") {
    res.render("auth/signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
    if (user !== null) {
      res.render("auth/signup", { message: "The username already exists" });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    const newUser = new User({
      username,
      password: hashPass
    });

    newUser.save()
      .then(() => {
        res.redirect("/");
      })
      .catch(err => {
        res.render("auth/signup", { message: "Something went wrong" });
      })
  });
});
router.get('/loggedin', (req, res, next) => {
  // req.isAuthenticated() is defined by passport
  if (req.isAuthenticated()) {
    res.status(200).json(req.user);
    return;
  }
  res.status(403).json({ message: 'Unauthorized' });
});

router.get('/logout', (req,res) => {
  req.logout();
  res.status(200).json({message:'logged out'})
});
// router.get("/logout", (req, res) => {
//   req.logout();
//   res.redirect("/");
// });

// router.get("/users", (req, res) => {
//   User.find()
//   .then(users =>{
//     res.status(200).json(users)
//   })
// });

module.exports = router;
