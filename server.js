import express from 'express';
import admin from 'firebase-admin';
import cors from 'cors';
import serviceAccount from './service-account-key.json' with { type: 'json' };

// Initialize the Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(express.json());
app.use(cors());
const PORT = process.env.PORT || 3000;
const db = admin.firestore();
const auth = admin.auth();

// VerifyToken middleware (unchanged)
// This just confirms the user is valid and gets their UID
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized: No token provided.');
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    req.user = await auth.verifyIdToken(idToken); 
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(401).send('Unauthorized: Invalid token.');
  }
};

// Existing endpoint (unchanged)
app.post('/api/assign-role', verifyToken, async (req, res) => {
  const { uid } = req.user; 
  console.log(`Assigning role to verified UID: ${uid}`);
  try {
    await auth.setCustomUserClaims(uid, { role: 'regular_user' });
    const userRolesRef = db.collection('user_roles').doc(uid);
    await userRolesRef.set({ role: 'regular_user' });
    res.status(200).send({ message: `Successfully assigned role to user ${uid}` });
  } catch (error) {
    console.error(`Error assigning role to UID: ${uid}`, error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});


// --- !!! UPDATED /api/create-request ENDPOINT !!! ---
app.post('/api/create-request', verifyToken, async (req, res) => {
  // Get the UID from the verified token
  const { uid } = req.user; 

  try {
    // 1. --- NEW LOGIC ---
    // Check the user's role in the Firestore database (the "source of truth")
    const userRoleDoc = await db.collection('user_roles').doc(uid).get();

    if (!userRoleDoc.exists || userRoleDoc.data().role !== 'medical_staff') {
      // This is the correct way to send a JSON error
      return res.status(403).json({ error: 'Forbidden: You do not have permission.' });
    }
    // -------------------

    // 2. Get data from the request body
    const { hospitalName, bloodType, unitsNeeded, isUrgent } = req.body;
    if (!hospitalName || !bloodType || !unitsNeeded) {
      return res.status(400).json({ error: 'Bad Request: Missing required fields.' });
    }

    // 3. Use ADMIN privileges to write to the collection
    await db.collection('blood_requests').add({
      hospitalName: hospitalName,
      bloodType: bloodType,
      unitsNeeded: Number(unitsNeeded),
      isUrgent: Boolean(isUrgent),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    
    // Send a JSON success response
    res.status(201).json({ message: 'Blood request created successfully.' });

  } catch (error) {
    console.error('Error creating blood request:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
