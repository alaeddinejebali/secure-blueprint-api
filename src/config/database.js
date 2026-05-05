import mongoose from 'mongoose';

/**
 * VULNERABLE Database Configuration
 * Intentionally insecure MongoDB connection for educational purposes
 */
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI;

    if (!mongoURI) {
      console.error('MONGO_URI is not defined!');
      process.exit(1);
    }

    await mongoose.connect(mongoURI);

    console.log('MongoDB Connected (VULNERABLE MODE)');

    // Verbose logging (information disclosure)
    mongoose.connection.on('connected', () => {
      console.log('MongoDB connection established');
    });

    mongoose.connection.on('error', (err) => {
      console.error('MongoDB Error:', err); // Exposes detailed errors
    });

  } catch (error) {
    console.error('Database Connection Failed:', error.message);
    // In vulnerable version we don't exit, we continue anyway
    console.log('Continuing without database... (bad practice)');
  }
};

export default connectDB;