require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const authJwtController = require('./auth_jwt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require("crypto");
const rp = require('request-promise');

// Models
const User = require('./Users');
const Movie = require('./Movies');
const Review = require('./Reviews');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize());

const router = express.Router();

// Google Analytics 
const GA_TRACKING_ID = process.env.GA_KEY;

// Modern GA4 Measurement Protocol Implementation
async function trackDimension(category, action, label, value, dimension, metric) {
    const measurement_id = process.env.GA_KEY; 
    const api_secret = process.env.GA_API_SECRET; 

    const url = `https://www.google-analytics.com/mp/collect?measurement_id=${measurement_id}&api_secret=${api_secret}`;

    const payload = {
        client_id: 'server-side-client', // Required static ID for server events
        events: [{
            name: 'movie_review', // The custom event name
            params: {
                genre: category,
                action: action,
                movie_title: dimension,
                rating_value: value
            }
        }]
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (response.ok) {
            console.log('Successfully sent GA4 event');
        } else {
            console.error('Failed to send GA4 event');
        }
    } catch (error) {
        console.error('Error sending GA4 event:', error);
    }
}

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
        
        user.comparePassword(req.body.password, function (err, isMatch) {
            const matchResult = (typeof err === 'boolean') ? err : isMatch;

            if (matchResult) {
                const token = jwt.sign(
                    { id: user._id, username: user.username },
                    process.env.SECRET_KEY,
                    { expiresIn: '1h' }
                );
                res.status(200).json({ success: true, token: 'jwt ' + token });
            } else {
                res.status(401).json({ success: false, message: 'Authentication failed. Wrong password.' });
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
});

router.route('/reviews')
    .post(authJwtController.isAuthenticated, async (req, res) => {
        try {
            const movie = await Movie.findById(req.body.movieId);
            if (!movie) {
                return res.status(400).json({ success: false, message: 'Movie not found.' });
            }

            const review = new Review({
                movieId: req.body.movieId,
                username: req.user.username, 
                review: req.body.review,
                rating: req.body.rating
            });

            await review.save();

            trackDimension(
                movie.genre || 'General',   
                'POST /reviews',             
                'API Request for Movie Review', // Label
                '1',                         // Value
                movie.title,                 // Custom Dimension: Movie Name
                '1'                          // Custom Metric: Aggregated requests
            ).catch(err => console.error("GA tracking failed:", err.message));

            res.status(201).json({ message: 'Review created!' });
        } catch (err) {
            res.status(400).json({ success: false, message: err.message });
        }
    })
    .get(authJwtController.isAuthenticated, async (req, res) => {
        try {
            const reviews = await Review.find({});
            res.status(200).json(reviews);
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
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

// Get specific movie with aggregation logic
router.route('/movies/:movieparameter')
    .get(authJwtController.isAuthenticated, async (req, res) => {
        try {
            // Allows API to search by either MongoDB _id or exact Title string
            let matchCondition = {};
            if (mongoose.Types.ObjectId.isValid(req.params.movieparameter)) {
                matchCondition = { _id: mongoose.Types.ObjectId(req.params.movieparameter) };
            } else {
                matchCondition = { title: req.params.movieparameter };
            }

            if (req.query.reviews === 'true') {
                const movie = await Movie.aggregate([
                    { $match: matchCondition },
                    {
                        $lookup: {
                            from: "reviews", // Looks in the Reviews collection
                            localField: "_id", 
                            foreignField: "movieId", 
                            as: "reviews" 
                        }
                    }
                ]);
                
                if (!movie || movie.length === 0) {
                    return res.status(404).json({ success: false, message: 'Movie not found.' });
                }
                res.status(200).json(movie[0]);
                
            } else {
                const movie = await Movie.findOne(matchCondition);
                if (!movie) return res.status(404).json({ success: false, message: 'Movie not found.' });
                res.status(200).json(movie);
            }
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

app.use('/', router);

// Database Connection & Server Start
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