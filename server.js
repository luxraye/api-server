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
    return res.status(401).json({ error: 'Unauthorized: No token provided.' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    req.user = await auth.verifyIdToken(idToken); 
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(401).json({ error: 'Unauthorized: Invalid token.' });
  }
};

// --- EXISTING ENDPOINTS (UNCHANGED) ---

// Assign role to new user
app.post('/api/assign-role', verifyToken, async (req, res) => {
  const { uid } = req.user; 
  try {
    await auth.setCustomUserClaims(uid, { role: 'regular_user' });
    const userRolesRef = db.collection('user_roles').doc(uid);
    await userRolesRef.set({ role: 'regular_user' });
    res.status(200).json({ message: `Successfully assigned role to user ${uid}` });
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Create a blood request
app.post('/api/create-request', verifyToken, async (req, res) => {
  const { uid } = req.user; 
  try {
    const userRoleDoc = await db.collection('user_roles').doc(uid).get();
    if (!userRoleDoc.exists || userRoleDoc.data().role !== 'medical_staff') {
      return res.status(403).json({ error: 'Forbidden: You do not have permission.' });
    }
    const { hospitalName, bloodType, unitsNeeded, isUrgent } = req.body;
    await db.collection('blood_requests').add({
      hospitalName,
      bloodType,
      unitsNeeded: Number(unitsNeeded),
      isUrgent: Boolean(isUrgent),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.status(201).json({ message: 'Blood request created successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Delete a blood request
app.delete('/api/requests/:id', verifyToken, async (req, res) => {
  const { uid } = req.user; 
  const { id } = req.params; 
  try {
    const userRoleDoc = await db.collection('user_roles').doc(uid).get();
    if (!userRoleDoc.exists || userRoleDoc.data().role !== 'medical_staff') {
      return res.status(403).json({ error: 'Forbidden: You do not have permission.' });
    }
    await db.collection('blood_requests').doc(id).delete();
    res.status(200).json({ message: 'Request deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// --- !!! NEW ENDPOINT TO REGISTER A DONATION !!! ---
app.post('/api/register-donation', verifyToken, async (req, res) => {
  const { uid: medicalStaffUid } = req.user; // UID of the staff member
  const { donorUid, location, bloodUnitID } = req.body; // Data for the donation

  if (!donorUid || !location || !bloodUnitID) {
    return res.status(400).json({ error: 'Bad Request: Missing required fields.' });
  }

  try {
    // 1. Verify the user is medical staff
    const userRoleDoc = await db.collection('user_roles').doc(medicalStaffUid).get();
    if (!userRoleDoc.exists || userRoleDoc.data().role !== 'medical_staff') {
      return res.status(403).json({ error: 'Forbidden: You do not have permission.' });
    }
    
    // 2. Verify the donor user actually exists
    await auth.getUser(donorUid); 

    // 3. Use ADMIN privileges to write to the donor's subcollection
    const historyRef = db.collection('user_profiles').doc(donorUid)
                         .collection('donation_history');
                         
    await historyRef.add({
      donatedAt: admin.firestore.FieldValue.serverTimestamp(),
      location: location,
      status: "Verified", // This is the first "on-chain" status
      bloodUnitID: bloodUnitID,
      registeredBy: medicalStaffUid, // Audit trail
    });
    
    res.status(201).json({ message: `Donation registered for user ${donorUid}` });

  } catch (error) {
    if (error.code === 'auth/user-not-found') {
      return res.status(404).json({ error: 'Donor user not found.' });
    }
    console.error('Error registering donation:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

