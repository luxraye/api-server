import express from 'express';
import admin from 'firebase-admin';
import serviceAccount from './service-account-key.json' with { type: 'json' };
import cors from 'cors';

// Initialize the Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(express.json());
app.use(cors());
const PORT = process.env.PORT || 3000;

// Middleware to verify Firebase ID Token
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized: No token provided.');
  }

  const idToken = authHeader.split('Bearer ')[1];

  try {
    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.uid = decodedToken.uid; // Add the uid to the request object
    next(); // Move to the next function
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(401).send('Unauthorized: Invalid token.');
  }
};

/**
 * NEW, SECURE ENDPOINT
 * This is called by our React app *after* a user successfully signs up.
 * It uses the verifyToken middleware to make sure the request is valid.
 */
app.post('/api/assign-role', verifyToken, async (req, res) => {
  // By the time we get here, the verifyToken middleware has already
  // run and added the user's UID to the request object.
  const { uid } = req;
  
  console.log(`Assigning role to verified UID: ${uid}`);

  try {
    // 1. Set custom claims for the user
    await admin.auth().setCustomUserClaims(uid, { role: 'regular_user' });

    // 2. Create the role document in Firestore
    const userRolesRef = admin.firestore().collection('user_roles').doc(uid);
    await userRolesRef.set({ role: 'regular_user' });

    console.log(`Successfully assigned role to UID: ${uid}`);
    res.status(200).send({ message: `Successfully assigned role to user ${uid}` });
  
  } catch (error) {
    console.error(`Error assigning role to UID: ${uid}`, error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});