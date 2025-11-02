import express from 'express';
import admin from 'firebase-admin';
import cors from 'cors';
import serviceAccount from './service-account-key.json' with { type: 'json' };

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(express.json());
app.use(cors());
const PORT = process.env.PORT || 3000;
const db = admin.firestore();
const auth = admin.auth();

// Middleware to verify Firebase ID Token
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ error: 'Unauthorized: No token provided.' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    req.user = await auth.verifyIdToken(idToken);
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(401).send({ error: 'Unauthorized: Invalid token.' });
  }
};

// --- Endpoint: Assign Role ---
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

// --- Endpoint: Create Request ---
app.post('/api/create-request', verifyToken, async (req, res) => {
  const { uid } = req.user;
  const userRoleDoc = await db.collection('user_roles').doc(uid).get();
  const userRole = userRoleDoc.data()?.role;

  if (userRole !== 'medical_staff') {
    return res.status(403).send({ error: 'Forbidden: You do not have permission.' });
  }

  const { hospitalName, bloodType, unitsNeeded, isUrgent } = req.body;
  if (!hospitalName || !bloodType || !unitsNeeded) {
    return res.status(400).send({ error: 'Bad Request: Missing required fields.' });
  }

  try {
    await db.collection('blood_requests').add({
      hospitalName,
      bloodType,
      unitsNeeded: Number(unitsNeeded),
      isUrgent: Boolean(isUrgent),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.status(201).send({ message: 'Blood request created successfully.' });
  } catch (error) {
    console.error('Error creating blood request:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// --- Endpoint: Delete Request ---
app.delete('/api/requests/:requestId', verifyToken, async (req, res) => {
  const { uid } = req.user;
  const userRoleDoc = await db.collection('user_roles').doc(uid).get();
  const userRole = userRoleDoc.data()?.role;

  if (userRole !== 'medical_staff') {
    return res.status(403).send({ error: 'Forbidden: You do not have permission.' });
  }

  const { requestId } = req.params;
  if (!requestId) {
    return res.status(400).send({ error: 'Bad Request: Missing request ID.' });
  }

  try {
    const docRef = db.collection('blood_requests').doc(requestId);
    await docRef.delete();
    res.status(200).send({ message: 'Request deleted successfully.' });
  } catch (error) {
    console.error('Error deleting request:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// --- Endpoint: Register Donation ---
app.post('/api/register-donation', verifyToken, async (req, res) => {
  const { uid } = req.user;
  const userRoleDoc = await db.collection('user_roles').doc(uid).get();
  const userRole = userRoleDoc.data()?.role;

  if (userRole !== 'medical_staff') {
    return res.status(403).send({ error: 'Forbidden: You do not have permission.' });
  }

  const { donorUID, location, bloodType, bloodUnitID } = req.body;
  if (!donorUID || !location || !bloodType || !bloodUnitID) {
    return res.status(400).send({ error: 'Bad Request: Missing required fields.' });
  }

  try {
    const timestamp = new Date();
    const newStatusEntry = {
      status: "Verified",
      location: location,
      timestamp: timestamp,
    };

    // 1. Write to the public, immutable ledger
    const ledgerRef = db.collection('blockchain_ledger').doc(bloodUnitID);
    await ledgerRef.set({
      bloodUnitID: bloodUnitID,
      donorUID: donorUID,
      bloodType: bloodType,
      donatedAt: timestamp,
      currentStatus: "Verified",
      location: location,
      statusHistory: [newStatusEntry] // Create the history array
    });

    // 2. Write to the user's private, deprecated history (for now)
    const historyRef = db.collection('user_profiles').doc(donorUID).collection('donation_history').doc(bloodUnitID);
    await historyRef.set({
      donatedAt: timestamp,
      location: location,
      status: "Verified",
      bloodUnitID: bloodUnitID
    });
    
    res.status(201).send({ message: 'Donation registered successfully.' });
  } catch (error) {
    console.error('Error registering donation:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// --- Endpoint: Update Status ---
app.post('/api/update-status', verifyToken, async (req, res) => {
  const { uid } = req.user;
  const userRoleDoc = await db.collection('user_roles').doc(uid).get();
  const userRole = userRoleDoc.data()?.role;

  if (userRole !== 'medical_staff') {
    return res.status(403).send({ error: 'Forbidden: You do not have permission.' });
  }

  // --- DEBUGGING: Log the received body ---
  console.log('Update status request received. Body:', req.body);
  // -------------------------------------

  const { bloodUnitID, newStatus, location } = req.body;
  if (!bloodUnitID || !newStatus || !location) {
    console.error('Validation failed. One or more fields are missing.', req.body);
    return res.status(400).send({ error: 'Bad Request: Missing required fields.' });
  }

  try {
    const timestamp = new Date();
    const newStatusEntry = {
      status: newStatus,
      location: location,
      timestamp: timestamp,
    };
    
    const ledgerRef = db.collection('blockchain_ledger').doc(bloodUnitID);

    // Atomically add the new status to the history array and update current status
    await ledgerRef.update({
      currentStatus: newStatus,
      location: location,
      statusHistory: admin.firestore.FieldValue.arrayUnion(newStatusEntry)
    });
    
    res.status(200).send({ message: 'Status updated successfully.' });
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

