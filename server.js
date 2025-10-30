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

// VerifyToken middleware
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

// --- Endpoint: Assign role to new user ---
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

// --- Endpoint: Create a blood request (Medical Staff) ---
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

// --- Endpoint: Delete a blood request (Medical Staff) ---
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

// --- Endpoint: Register a new donation (Medical Staff) ---
app.post('/api/register-donation', verifyToken, async (req, res) => {
  const { uid: medicalStaffUid } = req.user; // UID of the staff member
  const { donorUid, location, bloodUnitID, bloodType } = req.body; // Data for the donation

  if (!donorUid || !location || !bloodUnitID || !bloodType) {
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

    // --- ATOMIC BATCH WRITE ---
    const batch = db.batch();

    // 3A. Write to the PUBLIC "blockchain_ledger"
    const publicRef = db.collection('blockchain_ledger').doc(bloodUnitID);
    batch.set(publicRef, {
      donorId: donorUid, // This links the block to the user
      registeredAt: admin.firestore.FieldValue.serverTimestamp(),
      bloodType: bloodType,
      currentLocation: location,
      statusHistory: [ // This is the audit trail
        {
          status: "Verified",
          location: location,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          registeredBy: medicalStaffUid
        }
      ]
    });

    // 3B. Write to the PRIVATE "donation_history" (for user's convenience)
    const privateRef = db.collection('user_profiles').doc(donorUid)
                         .collection('donation_history').doc(bloodUnitID); // Use same ID
    batch.set(privateRef, {
      ledgerId: bloodUnitID, // This points to the public record
      donatedAt: admin.firestore.FieldValue.serverTimestamp(),
      location: location,
      status: "Verified"
    });
    
    // 4. Commit the atomic write
    await batch.commit();
    
    res.status(201).json({ message: `Donation ${bloodUnitID} registered for user ${donorUid}` });

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

