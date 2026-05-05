import User from '../models/User.js';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'superweaksecret123';

// Very weak auth controller

export const register = async (req, res) => {
    try {
        const user = await User.create(req.body);   // No validation
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);

        res.status(201).json({ message: 'User created', token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

export const login = async (req, res) => {
    try {
        const {email, password} = req.body;

        const user = await User.findOne({ email });
        // Very weak password comparison
        if(!user || user.password !== password) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
