import mongoose from 'mongoose';

/**
 * Connects to MongoDB and exits the process on failure.
 *
 * SECURITY: The connection URI comes exclusively from the environment variable
 * MONGO_URI — it is never hardcoded. Hardcoding credentials in source code
 * exposes them in version control history forever.
 *
 * Unlike the vulnerable version, a failed connection exits the process
 * immediately. Continuing without a database causes all subsequent queries
 * to buffer and eventually time out — giving callers false hope and leaking
 * timeout error details.
 */
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI;

    if (!mongoURI) {
      console.error('MONGO_URI environment variable is not set. Exiting.');
      process.exit(1);
    }

    await mongoose.connect(mongoURI);
    console.log('MongoDB connected.');

  } catch (error) {
    // Log the error server-side for diagnostics but do not expose it to clients.
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  }
};

export default connectDB;
