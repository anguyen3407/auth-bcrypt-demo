const express = require('express');
const bodyPaser = require('body-parser');
const session = require('express-session');
const massive = require('massive');
const bcrypt = require('bcrypt');

require('dotenv').config();
const app = express();
massive(process.env.CONNECTION_STRING).then(db => app.set('db', db));

app.use(bodyPaser.json());
app.use(session({
  secret: "mega hyper ultra secret",
  saveUninitialized: false,
  resave: false,
}));

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password,12).then(hashedPassword => {
    app.get('db').create_user([username, hashedPassword]).then(() => {
      req.session.user = { username };
      res.json({ username });
    }).catch(error => {
      console.log('error', error);
      res.status(400).json({ message: "An error occurred; for security reasons it can't be disclosed" });
    });
  })

});

app.post('/login', (req, res) => {
  //use bcrypt docs for bcrypt.compare password and hash
  const { username, password } = req.body;
  app.get('db').find_user([username]).then(data => {
    if (data.length) {
      if (data[0].password === password) {
        req.session.user = { username };
        res.json({ username });
      } else {
        res.status(403).json({ message: 'Invalid password' });
      }
    } else {
      res.status(403).json({ message: 'Unknown user' });
    }
  }).catch(error => {
    console.log('error', error);
    res.status(400).json({ message: "An undisclosable error occurred " });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.send();
});

function ensureLoggedIn(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.status(403).json({ message: 'You are not authorized' });
  }
}

app.get('/secure-data', ensureLoggedIn, (req, res) => {
  res.json({ someSecureData: 123 });
});

const PORT = 3030;
app.listen(PORT, () => {
  console.log('Server listening on port ' + PORT);
});


// bcrypt.hash('mypassword', 12).then(hashedPassword => {
//   console.log('hashedPassword', hashedPassword);
// });