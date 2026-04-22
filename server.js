require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const authJwtController = require('./auth_jwt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

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

// Google Analytics (Refactored without try/catch)
function trackDimension(category, action, label, value, dimension, metric) {
    const measurement_id = process.env.GA_KEY; 
    const api_secret = process.env.GA_API_SECRET; 

    // Safety check in case the env variables are missing
    if (!measurement_id || !api_secret) return;

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

    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (response.ok) {
            console.log(`Successfully sent GA4 event for: ${dimension}`);
        } else {
            console.error('Failed to send GA4 event');
        }
    })
    .catch(error => console.error('Error sending GA4 event:', error));
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

            // Calling our new try-catch-free tracking function
            trackDimension(
                movie.genre || 'General',   
                'POST /reviews',             
                'API Request for Movie Review', 
                '1',                         
                movie.title,                 
                '1'                          
            );

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

    router.route('/movies/search')
    .post(authJwtController.isAuthenticated, async (req, res) => {
    const searchTerm = req.body.searchTerm;
    if (!searchTerm) {
        return res.status(400).json({ success: false, message: 'Please provide a searchTerm' });
    }

    try {
        // Create a Case-Insensitive Regular Expression for partial matching
        const regex = new RegExp(searchTerm, 'i');

        const aggregate = [
            {
                $match: {
                    $or: [
                        { title: { $regex: regex } },
                        { "actors.actorName": { $regex: regex } }
                    ]
                }
            },
            {
                $lookup: {
                    from: 'reviews',
                    localField: '_id',
                    foreignField: 'movieId',
                    as: 'reviews'
                }
            },
            {
                $addFields: {
                    avgRating: { $avg: '$reviews.rating' }
                }
            }
        ];

        const movies = await Movie.aggregate(aggregate);
        res.status(200).json(movies);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
    });



// Get specific movie with aggregation logic
router.route('/movies/:movieparameter')
    .get(authJwtController.isAuthenticated, async (req, res) => {
        try {
            let matchCondition = {};
            if (mongoose.Types.ObjectId.isValid(req.params.movieparameter)) {
                // FIX: Added 'new' keyword so Mongoose doesn't crash on lookup
                matchCondition = { _id: new mongoose.Types.ObjectId(req.params.movieparameter) };
            } else {
                matchCondition = { title: req.params.movieparameter };
            }

            if (req.query.reviews === 'true') {
                const movie = await Movie.aggregate([
                    { $match: matchCondition },
                    {
                        $lookup: {
                            from: "reviews", 
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
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});

// Database Connection (Happens in the background)
mongoose.connect(process.env.DB)
    .then(() => {
        console.log("Connected to MongoDB successfully!");
    })
    .catch((err) => {
        console.error("FATAL MongoDB connection error:", err);
    });

module.exports = app;