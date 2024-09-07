const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');
const http = require('http');
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());

// Database connection
mongoose.connect('mongodb://localhost:27017/game', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    wins: Number,
    losses: Number,
});

const User = mongoose.model('User', userSchema);

// Authentication Route (Signup/Login)
app.post('/auth/signup', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ username, password: hashedPassword, wins: 0, losses: 0 });
    await user.save();
    res.json({ message: 'User signed up successfully' });
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, 'secretkey', { expiresIn: '1h' });
    res.json({ token });
});

// Middleware to check JWT authentication
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Get user stats
app.get('/user/stats', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.userId);
    res.json({ wins: user.wins, losses: user.losses });
});

// Matchmaking
let waitingPlayers = [];

io.on('connection', (socket) => {
    socket.on('find_match', (userId) => {
        // Add the player to the waiting list
        waitingPlayers.push({ socketId: socket.id, userId });

        // If there are two players in the waiting list, start the game
        if (waitingPlayers.length >= 2) {
            const player1 = waitingPlayers.pop();
            const player2 = waitingPlayers.pop();

            // Inform both players that the match is starting
            io.to(player1.socketId).emit('match_found', { opponentId: player2.userId });
            io.to(player2.socketId).emit('match_found', { opponentId: player1.userId });
        }
    });

    socket.on('game_action', (actionData) => {
        // Broadcast game actions to the opponent
        const opponentSocketId = getOpponentSocketId(socket.id);
        io.to(opponentSocketId).emit('game_update', actionData);
    });
    
    // Handle player disconnect
    socket.on('disconnect', () => {
        waitingPlayers = waitingPlayers.filter(p => p.socketId !== socket.id);
    });
});

const getOpponentSocketId = (socketId) => {
    // Logic to get opponent's socket ID
    // You will have to track players in a match
};

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
