import express from 'express';
import admin from 'firebase-admin';
import cors from 'cors'; // Import cors
import serviceAccount from './service-account-key.json' with { type: 'json' };

// Initialize the Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(express.json());
app.use(cors()); // Use cors
const PORT = process.env.PORT || 3000;
const db = admin.firestore();
const auth = admin.auth();

// --- UPDATED TOKEN VERIFICATION MIDDLEWARE ---
// This now adds the user's decoded token (including claims) to req.user
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized: No token provided.');
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    req.user = await auth.verifyIdToken(idToken); // Add decoded token to request
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(401).send('Unauthorized: Invalid token.');
  }
};

// --- EXISTING ENDPOINT (Unchanged) ---
app.post('/api/assign-role', verifyToken, async (req, res) => {
  const { uid } = req.user; // Get uid from our middleware
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

// --- !!! NEW ENDPOINT FOR MEDICAL STAFF !!! ---
app.post('/api/create-request', verifyToken, async (req, res) => {
  const { role } = req.user; // Get the user's role from their token
  
  // 1. Verify the user is medical staff
  if (role !== 'medical_staff') {
    return res.status(403).send('Forbidden: You do not have permission.');
  }

  // 2. Get data from the request body
  const { hospitalName, bloodType, unitsNeeded, isUrgent } = req.body;
  if (!hospitalName || !bloodType || !unitsNeeded) {
    return res.status(400).send('Bad Request: Missing required fields.');
  }

  try {
    // 3. Use ADMIN privileges to write to the collection
    await db.collection('blood_requests').add({
      hospitalName: hospitalName,
      bloodType: bloodType,
      unitsNeeded: Number(unitsNeeded),
      isUrgent: Boolean(isUrgent),
      createdAt: admin.firestore.FieldValue.serverTimestamp(), // Use server time
    });
    
    res.status(201).send({ message: 'Blood request created successfully.' });

  } catch (error) {
    console.error('Error creating blood request:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});