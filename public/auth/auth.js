// File: auth.js
// Your central library for managing login sessions across all projects.

const AuthManager = {
    init: function(firebaseConfig) {
        if (!firebase.apps.length) {
            firebase.initializeApp(firebaseConfig);
        }
        this.db = firebase.firestore(); // This is our "Filing Cabinet"
        this.auth = firebase.auth();     // This is our "Security Guard"
        console.log("AuthManager Initialized.");
    },

    login: async function(mobileNumber, password) {
        // Step 1: Check the user's details in the "Filing Cabinet" (Firestore).
        const snapshot = await this.db.collection('users').where('mobileNumber', '==', mobileNumber).get();
        if (snapshot.empty) {
            throw new Error("User not found.");
        }
        const userDoc = snapshot.docs[0];
        const userData = { id: userDoc.id, ...userDoc.data() };

        if (userData.password !== password) {
            throw new Error("Incorrect password.");
        }

        // Step 2: If details are correct, tell the "Security Guard" (Firebase Auth) to create a session.
        // We create a unique "system email" that the user never sees.
        const systemEmail = `${userData.id}@xperts-data.app`; 
        const systemPassword = password;

        try {
            await this.auth.signInWithEmailAndPassword(systemEmail, systemPassword);
        } catch (error) {
            if (error.code === 'auth/user-not-found') {
                // If this is the first time, create a record for them with the Security Guard.
                await this.auth.createUserWithEmailAndPassword(systemEmail, systemPassword);
            } else {
                throw new Error("Could not create secure session.");
            }
        }
        
        return userData; // Return the full user profile from the Filing Cabinet.
    },

    logout: async function() {
        // Tell the Security Guard to revoke the session.
        await this.auth.signOut();
        localStorage.clear();
    },

    getCurrentUser: function() {
        // Ask the Security Guard if anyone is currently logged in.
        return new Promise((resolve) => {
            const unsubscribe = this.auth.onAuthStateChanged(user => {
                unsubscribe();
                resolve(user); // Returns the Security Guard's record of the user.
            });
        });
    },
    
    getUserProfile: async function() {
        // Step 1: Ask the Security Guard who is logged in.
        const firebaseUser = await this.getCurrentUser();
        
        if (firebaseUser) {
            // Step 2: If someone is logged in, get their unique ID.
            const userId = firebaseUser.email.split('@')[0];
            
            // Step 3: Use that ID to get their full details from the "Filing Cabinet" (Firestore).
            const userDoc = await this.db.collection('users').doc(userId).get();
            if (userDoc.exists) {
                return { id: userDoc.id, ...userDoc.data() };
            }
        }
        return null; // No one is logged in.
    }
};
