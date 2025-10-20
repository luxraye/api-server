import express from 'express';
import admin from 'firebase-admin';

// Import your service account key
import serviceAccount from '../service-account-key.json' with { type: 'json' };

// Initialize the Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(express.json()); // Middleware to parse JSON bodies

const PORT = process.env.PORT || 3000;

// This is the endpoint Firebase will call when a new user signs up
app.post('/api/handle-new-user', async (req, res) => {
  console.log('Received new user data:', req.body);
  
  const { uid } = req.body; // Extract user ID from the request

  if (!uid) {
    return res.status(400).send('User ID (uid) is missing.');
  }

  try {
    // This is the same logic from our old cloud function
    await admin.auth().setCustomUserClaims(uid, { role: 'regular_user' });
    const userRolesRef = admin.firestore().collection('user_roles').doc(uid);
    await userRolesRef.set({ role: 'regular_user' });

    console.log(`Successfully assigned role to UID: ${uid}`);
    res.status(200).send(`Successfully assigned role to user ${uid}`);
  } catch (error) {
    console.error(`Error assigning role to UID: ${uid}`, error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});