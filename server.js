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

// Existing endpoint (unchanged)
app.post('/api/create-request', verifyToken, async (req, res) => {
  const { uid } = req.user; 
  try {
    const userRoleDoc = await db.collection('user_roles').doc(uid).get();
    if (!userRoleDoc.exists || userRoleDoc.data().role !== 'medical_staff') {
      return res.status(403).json({ error: 'Forbidden: You do not have permission.' });
    }
    const { hospitalName, bloodType, unitsNeeded, isUrgent } = req.body;
    if (!hospitalName || !bloodType || !unitsNeeded) {
      return res.status(400).json({ error: 'Bad Request: Missing required fields.' });
    }
    await db.collection('blood_requests').add({
      hospitalName: hospitalName,
      bloodType: bloodType,
      unitsNeeded: Number(unitsNeeded),
      isUrgent: Boolean(isUrgent),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.status(201).json({ message: 'Blood request created successfully.' });
  } catch (error) {
    console.error('Error creating blood request:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// --- !!! NEW ENDPOINT TO DELETE A REQUEST !!! ---
app.delete('/api/requests/:id', verifyToken, async (req, res) => {
  const { uid } = req.user; // Get the user's UID
  const { id } = req.params; // Get the document ID from the URL (e.g., /api/requests/XYZ123)

  try {
    // 1. Verify the user is medical staff
    const userRoleDoc = await db.collection('user_roles').doc(uid).get();
    if (!userRoleDoc.exists || userRoleDoc.data().role !== 'medical_staff') {
      return res.status(403).json({ error: 'Forbidden: You do not have permission.' });
    }

    // 2. Use ADMIN privileges to delete the document
    await db.collection('blood_requests').doc(id).delete();
    
    res.status(200).json({ message: 'Request deleted successfully.' });

  } catch (error) {
    console.error(`Error deleting request ${id}:`, error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

