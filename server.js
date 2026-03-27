require('dotenv').config(); 

const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const authJwtController = require('./auth_jwt'); 
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose'); 
const User = require('./Users');
const Movie = require('./Movies'); 

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize());

const router = express.Router();

router.post('/signup', async (req, res) => { 
  if (!req.body.username || !req.body.password) {
    return res.status(400).json({ success: false, msg: 'Please include both username and password to signup.' }); 
  }

  try {
    const user = new User({ 
      name: req.body.name,
      username: req.body.username,
      password: req.body.password,
    });

    await user.save(); 
    res.status(201).json({ success: true, msg: 'Successfully created new user.' }); 
  } catch (err) {
    if (err.code === 11000) { 
      return res.status(409).json({ success: false, message: 'A user with that username already exists.' }); 
    } else {
      console.error(err); 
      return res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' }); 
    }
  }
});

router.post('/signin', async (req, res) => {
    if (!req.body.username || !req.body.password) {
        return res.status(400).json({ success: false, message: 'Please include both username and password to sign in.' });
    }

    try {
        const user = await User.findOne({ username: req.body.username }).select('+password');
        
        if (!user) {
            return res.status(401).json({ success: false, message: 'Authentication failed. User not found.' });
        }
        const isMatch = await user.comparePassword(req.body.password);
        
        if (isMatch) {
            const token = jwt.sign(
                { id: user._id, username: user.username }, 
                process.env.SECRET_KEY, 
                { expiresIn: '1h' } 
            );
            res.status(200).json({ success: true, token: 'jwt ' + token });
        } else {
            res.status(401).json({ success: false, message: 'Authentication failed. Wrong password.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

router.route('/movies')
    .get(authJwtController.isAuthenticated, async (req, res) => {
        try {
            const movies = await Movie.find({});
            res.status(200).json(movies);
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    })
    .post(authJwtController.isAuthenticated, async (req, res) => {
        if (!req.body.title || !req.body.actors || req.body.actors.length < 3) {
            return res.status(400).json({ success: false, message: 'Movie must include a title and at least three actors.' });
        }
        try {
            const movie = new Movie(req.body);
            await movie.save();
            res.status(201).json({ success: true, message: 'Movie created successfully.', movie: movie });
        } catch (err) {
            res.status(400).json({ success: false, message: err.message });
        }
    })
    .put(authJwtController.isAuthenticated, (req, res) => {
        res.status(405).json({ success: false, message: 'PUT request not supported on /movies' });
    })
    .delete(authJwtController.isAuthenticated, (req, res) => {
        res.status(405).json({ success: false, message: 'DELETE request not supported on /movies' });
    });

router.route('/movies/:movieparameter')
    .get(authJwtController.isAuthenticated, async (req, res) => {
        try {
            const movie = await Movie.findOne({ title: req.params.movieparameter });
            if (!movie) return res.status(404).json({ success: false, message: 'Movie not found.' });
            res.status(200).json(movie);
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    })
    .post(authJwtController.isAuthenticated, (req, res) => {
        res.status(405).json({ success: false, message: 'POST request not supported on /movies/:movieparameter' });
    })
    .put(authJwtController.isAuthenticated, async (req, res) => {
        try {
            const movie = await Movie.findOneAndUpdate(
                { title: req.params.movieparameter },
                req.body,
                { new: true }
            );
            if (!movie) return res.status(404).json({ success: false, message: 'Movie not found.' });
            res.status(200).json({ success: true, message: 'Movie updated successfully.', movie: movie });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    })
    .delete(authJwtController.isAuthenticated, async (req, res) => {
        try {
            const movie = await Movie.findOneAndDelete({ title: req.params.movieparameter });
            if (!movie) return res.status(404).json({ success: false, message: 'Movie not found.' });
            res.status(200).json({ success: true, message: 'Movie deleted successfully.' });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

app.use('/', router);

mongoose.connect(process.env.DB)
    .then(() => {
        console.log(" Connected to MongoDB successfully!");
        const PORT = process.env.PORT || 8080; 
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch((err) => {
        console.error(" FATAL MongoDB connection error:", err);
    });

module.exports = app;