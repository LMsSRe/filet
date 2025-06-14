import React, { useState, useEffect, useRef } from 'react';
import { initializeApp } from 'firebase/app';
import { 
    getAuth, 
    createUserWithEmailAndPassword, 
    signInWithEmailAndPassword, 
    signOut, 
    onAuthStateChanged,
    sendEmailVerification 
} from 'firebase/auth';
import { 
    getFirestore, 
    collection, 
    addDoc, 
    query, 
    where, 
    getDocs, 
    doc, 
    deleteDoc,
    onSnapshot 
} from 'firebase/firestore';
import { 
    getStorage, 
    ref, 
    uploadBytesResumable, 
    getDownloadURL, 
    deleteObject 
} from 'firebase/storage';

// --- Helper Components: Icons ---
const UploadCloudIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mx-auto h-12 w-12 text-gray-400">
        <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"></path>
        <path d="M12 12v9"></path><path d="m16 16-4-4-4 4"></path>
    </svg>
);
const DownloadIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
);
const TrashIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><line x1="10" y1="11" x2="10" y2="17" /><line x1="14" y1="11" x2="14" y2="17" /></svg>
);


// --- Custom Hook to load external scripts ---
const useScript = (url) => {
    const [status, setStatus] = useState(url ? 'loading' : 'idle');

    useEffect(() => {
        if (!url) {
            setStatus('idle');
            return;
        }

        let script = document.querySelector(`script[src="${url}"]`);

        if (!script) {
            script = document.createElement('script');
            script.src = url;
            script.async = true;
            document.body.appendChild(script);

            const setAttributeFromEvent = (event) => {
                setStatus(event.type === 'load' ? 'ready' : 'error');
            };

            script.addEventListener('load', setAttributeFromEvent);
            script.addEventListener('error', setAttributeFromEvent);
            
            return () => {
                if(script.parentNode) {
                    script.removeEventListener('load', setAttributeFromEvent);
                    script.removeEventListener('error', setAttributeFromEvent);
                }
            };
        } else {
             setStatus(script.getAttribute('data-status') || 'ready');
        }
        
    }, [url]);

    return status;
};


// --- Helper Functions ---
// These functions will only be called after the crypto script is loaded
const generateKey = () => window.CryptoJS.lib.WordArray.random(32).toString();
const encryptFile = (file, key) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            try {
                const wordArray = window.CryptoJS.lib.WordArray.create(reader.result);
                const encrypted = window.CryptoJS.AES.encrypt(wordArray, key).toString();
                resolve(new Blob([encrypted]));
            } catch (error) {
                console.error("Encryption error:", error);
                reject(error);
            }
        };
     reader.onerror = (error) => {
            console.error("File reading error:", error);
            reject(error);
        };
        reader.readAsArrayBuffer(file);
    });
};

const decryptFile = (encryptedBlob, key) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            try {
                const decrypted = window.CryptoJS.AES.decrypt(reader.result, key);
                if (!decrypted.sigBytes) {
                   throw new Error("Decryption failed: could not decrypt data.");
                }
                const typedArray = convertWordArrayToUint8Array(decrypted);
                resolve(new Blob([typedArray]));
            } catch (error) {
                console.error("Decryption error:", error);
                reject(error);
            }
        };
        reader.onerror = (error) => {
             console.error("Blob reading error:", error);
             reject(error);
        };
        reader.readAsText(encryptedBlob);
    });
};

const convertWordArrayToUint8Array = (wordArray) => {
    const l = wordArray.sigBytes;
    const u8_array = new Uint8Array(l);
    for (let i = 0; i < l; i++) {
        u8_array[i] = (wordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return u8_array;
};


// --- Firebase Configuration ---
// IMPORTANT: Replace with your actual Firebase config
const firebaseConfig = {
  apiKey: "AIzaSyBIBqcf1uRrYcp521fCff5TGXl0zZ_QZZE",
  authDomain: "fileweb-92b97.firebaseapp.com",
  projectId: "fileweb-92b97",
  storageBucket: "fileweb-92b97.firebasestorage.app",
  messagingSenderId: "285809549564",
  appId: "1:285809549564:web:52bbde65ea01d05449b779"
};

// --- Initialize Firebase ---
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const storage = getStorage(app);

// --- React Components ---

const Modal = ({ isOpen, onClose, onConfirm, title, children }) => {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-slate-900 bg-opacity-60 z-50 flex justify-center items-center backdrop-blur-sm">
            <div className="bg-white p-6 rounded-lg shadow-xl max-w-sm w-full mx-4 transform transition-all duration-300 scale-95 opacity-0 animate-scale-in">
                <h3 className="text-lg font-bold text-slate-800 mb-4">{title}</h3>
                <div className="mb-6 text-slate-600">{children}</div>
                <div className="flex justify-end space-x-4">
                    <button onClick={onClose} className="px-4 py-2 bg-slate-200 text-slate-800 rounded-lg hover:bg-slate-300 transition-colors">Cancel</button>
                    {onConfirm && <button onClick={onConfirm} className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors">Confirm</button>}
                </div>
            </div>
        </div>
    );
};

const AuthComponent = ({ setUser }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isRegister, setIsRegister] = useState(true);
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setMessage('');

        if (isRegister) {
            try {
                const userCredential = await createUserWithEmailAndPassword(auth, email, password);
                await sendEmailVerification(userCredential.user);
                setMessage('Registration successful! Please check your email for a verification link.');
            } catch (err) {
                setError(err.message);
            }
        } else {
            try {
                const userCredential = await signInWithEmailAndPassword(auth, email, password);
                await userCredential.user.reload();
                if (!userCredential.user.emailVerified) {
                    setError('Please verify your email before logging in.');
                    await signOut(auth);
                    return;
                }
                setUser(userCredential.user);
            } catch (err) {
                setError(err.message);
            }
        }
    };

    return (
        <div className="max-w-md mx-auto mt-10">
             <div className="bg-white p-8 rounded-xl shadow-lg">
                <h2 className="text-3xl font-bold mb-6 text-center text-slate-800">{isRegister ? 'Create Account' : 'Welcome Back'}</h2>
                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="text-sm font-medium text-slate-600 block mb-2">Email Address</label>
                        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" required className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all" />
                    </div>
                    <div>
                        <label className="text-sm font-medium text-slate-600 block mb-2">Password</label>
                        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all" />
                    </div>
                    <button type="submit" className="w-full bg-violet-600 text-white py-3 rounded-lg hover:bg-violet-700 transition-all duration-300 shadow-md hover:shadow-lg font-semibold">{isRegister ? 'Register' : 'Login'}</button>
                </form>
                {error && <p className="text-red-500 mt-4 text-center text-sm">{error}</p>}
                {message && <p className="text-green-500 mt-4 text-center text-sm">{message}</p>}
                <p className="mt-6 text-center text-sm">
                    <button onClick={() => setIsRegister(!isRegister)} className="text-violet-600 hover:underline font-medium">
                        {isRegister ? 'Already have an account? Login' : "Don't have an account? Register"}
                    </button>
                </p>
            </div>
        </div>
    );
};

const FileUpload = ({ user }) => {
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');
    const dragAreaRef = useRef(null);

    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];
        if (selectedFile && selectedFile.size > 10 * 1024 * 1024) {
            setError('File size must be less than 10MB.');
            setFile(null);
        } else if (selectedFile) {
            setFile(selectedFile);
            setError('');
            setMessage('');
        }
    };
    
    const handleDragEvents = (e, type) => {
        e.preventDefault();
        e.stopPropagation();
        if (type === 'dragover') dragAreaRef.current.classList.add('border-violet-500', 'bg-violet-50');
        else dragAreaRef.current.classList.remove('border-violet-500', 'bg-violet-50');
    }
    
    const handleDrop = (e) => {
        handleDragEvents(e, 'dragleave');
        const droppedFile = e.dataTransfer.files[0];
         if (droppedFile && droppedFile.size > 10 * 1024 * 1024) {
            setError('File size must be less than 10MB.');
            setFile(null);
        } else if (droppedFile) {
            setFile(droppedFile);
            setError('');
             setMessage('');
        }
    };

    const handleUpload = async () => {
        if (!file) {
            setError('Please select a file first.');
            return;
        }
        setUploading(true);
        setError('');
        setMessage('');
        setProgress(0);

        try {
            const encryptionKey = generateKey();
            const encryptedFileBlob = await encryptFile(file, encryptionKey);
            
            const storageRef = ref(storage, `files/${user.uid}/${Date.now()}_${file.name}.encrypted`);
            const uploadTask = uploadBytesResumable(storageRef, encryptedFileBlob);

            uploadTask.on('state_changed',
                (snapshot) => {
                    const currentProgress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
                    setProgress(currentProgress);
                },
                (error) => {
                    setError('Upload failed: ' + error.message);
                    setUploading(false);
                },
                async () => {
                    await addDoc(collection(db, 'files'), {
                        uid: user.uid,
                        ownerEmail: user.email,
                        name: file.name,
                        type: file.type,
                        size: file.size,
                        storagePath: uploadTask.snapshot.ref.fullPath,
                        encryptionKey: encryptionKey, 
                        createdAt: new Date(),
                    });
                    setMessage('File uploaded and encrypted successfully!');
                    setFile(null);
                    setUploading(false);
                }
            );

        } catch (err) {
            setError('Encryption or upload failed: ' + err.message);
            setUploading(false);
        }
    };

    return (
        <div className="bg-white p-8 rounded-xl shadow-lg mt-6">
            <h3 className="text-xl font-bold mb-4 text-slate-800">Upload New File</h3>
            <div 
              ref={dragAreaRef}
              className="border-2 border-dashed border-slate-300 rounded-xl p-8 text-center cursor-pointer transition-all duration-300 hover:border-violet-500 hover:bg-violet-50"
              onDragOver={(e) => handleDragEvents(e, 'dragover')}
              onDragLeave={(e) => handleDragEvents(e, 'dragleave')}
              onDrop={handleDrop}
              onClick={() => document.getElementById('file-upload').click()}
            >
                <input type="file" onChange={handleFileChange} className="hidden" id="file-upload" />
                <UploadCloudIcon />
                <p className="mt-4 font-semibold text-slate-700">Drag & drop a file here</p>
                <p className="text-sm text-slate-500 mt-1">or click to select a file</p>
                <p className="text-xs text-slate-400 mt-2">Max file size: 10MB</p>
            </div>

            {file && (
                <div className="mt-4 text-center font-semibold text-violet-700 bg-violet-100 p-3 rounded-lg">
                    Selected: {file.name}
                </div>
            )}
            
            <div className="mt-6">
                <button onClick={handleUpload} disabled={!file || uploading} className="w-full flex justify-center items-center bg-violet-600 text-white py-3 rounded-lg hover:bg-violet-700 transition-all duration-300 shadow-md hover:shadow-lg font-semibold disabled:bg-slate-400 disabled:cursor-not-allowed">
                    {uploading ? `Uploading...` : 'Upload & Encrypt'}
                </button>
            </div>
            {uploading && (
                <div className="w-full bg-slate-200 rounded-full h-2 mt-4 overflow-hidden">
                    <div className="bg-violet-500 h-2 rounded-full transition-all duration-300" style={{ width: `${progress}%` }}></div>
                </div>
            )}
             {error && <p className="text-red-500 mt-4 text-center text-sm">{error}</p>}
             {message && <p className="text-green-500 mt-4 text-center text-sm">{message}</p>}
        </div>
    );
};

const FileList = ({ user }) => {
    const [files, setFiles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
    const [fileToDelete, setFileToDelete] = useState(null);

    useEffect(() => {
        setLoading(true);
        const q = query(collection(db, "files"), where("uid", "==", user.uid));
        
        const unsubscribe = onSnapshot(q, (querySnapshot) => {
            const userFiles = [];
            querySnapshot.forEach((doc) => {
                userFiles.push({ id: doc.id, ...doc.data() });
            });
            userFiles.sort((a, b) => b.createdAt.toDate() - a.createdAt.toDate());
            setFiles(userFiles);
            setLoading(false);
        }, (err) => {
            setError('Failed to fetch files: ' + err.message);
            setLoading(false);
        });

        return () => unsubscribe();
    }, [user.uid]);

    const openDeleteModal = (file) => {
        setFileToDelete(file);
        setIsDeleteModalOpen(true);
    };

    const closeDeleteModal = () => {
        setFileToDelete(null);
        setIsDeleteModalOpen(false);
    };

    const confirmDelete = async () => {
        if (!fileToDelete) return;
        try {
            const fileRef = ref(storage, fileToDelete.storagePath);
            await deleteObject(fileRef);
            await deleteDoc(doc(db, "files", fileToDelete.id));
        } catch (err) {
            setError('Failed to delete file: ' + err.message);
        } finally {
            closeDeleteModal();
        }
    };

    const handleDownload = async (file) => {
        try {
            const fileRef = ref(storage, file.storagePath);
            const url = await getDownloadURL(fileRef);
            
            const response = await fetch(url);
            if (!response.ok) throw new Error('Network response was not ok');
            const encryptedBlob = await response.blob();
            
            const decryptedBlob = await decryptFile(encryptedBlob, file.encryptionKey);

            const downloadUrl = window.URL.createObjectURL(decryptedBlob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = downloadUrl;
            a.download = file.name;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(downloadUrl);
            a.remove();
            
        } catch (err) {
             setError('Failed to download or decrypt file: ' + err.message);
        }
    };

    return (
        <>
            <Modal
                isOpen={isDeleteModalOpen}
                onClose={closeDeleteModal}
                onConfirm={confirmDelete}
                title="Confirm Deletion"
            >
                <p>Are you sure you want to delete <span className="font-semibold text-slate-800">{fileToDelete?.name}</span>? This action cannot be undone.</p>
            </Modal>
            <div className="mt-10 bg-white p-8 rounded-xl shadow-lg">
                <h3 className="text-xl font-bold mb-6 text-slate-800">Your Encrypted Files</h3>
                {error && <p className="text-red-500 mb-4 text-sm">{error}</p>}
                {loading ? (
                    <p className="text-slate-500">Loading files...</p>
                ) : files.length === 0 ? (
                    <p className="text-slate-500 text-center py-8">You haven't uploaded any files yet.</p>
                ) : (
                    <ul className="space-y-3">
                        {files.map(file => (
                            <li key={file.id} className="flex flex-wrap items-center justify-between p-4 bg-slate-50 rounded-lg hover:bg-slate-100 transition-colors duration-300">
                                <div className="flex-1 min-w-0 pr-4">
                                    <p className="font-semibold text-slate-800 truncate">{file.name}</p>
                                    <p className="text-sm text-slate-500">
                                        {(file.size / 1024 / 1024).toFixed(2)} MB &bull; {new Date(file.createdAt.seconds * 1000).toLocaleDateString()}
                                    </p>
                                </div>
                                <div className="flex-shrink-0 space-x-2 mt-2 sm:mt-0">
                                    <button onClick={() => handleDownload(file)} className="p-2 text-slate-600 rounded-full hover:bg-violet-100 hover:text-violet-600 transition-colors"><DownloadIcon /></button>
                                    <button onClick={() => openDeleteModal(file)} className="p-2 text-slate-600 rounded-full hover:bg-red-100 hover:text-red-600 transition-colors"><TrashIcon /></button>
                                </div>
                            </li>
                        ))}
                    </ul>
                )}
            </div>
        </>
    );
};

export default function App() {
    const [user, setUser] = useState(null);
    const [authLoading, setAuthLoading] = useState(true);
    const cryptoScriptStatus = useScript('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js');

    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
            if (currentUser) {
                currentUser.reload().then(() => {
                    if (auth.currentUser.emailVerified) {
                        setUser(auth.currentUser);
                    } else {
                        setUser(null);
                    }
                    setAuthLoading(false);
                });
            } else {
                setUser(null);
                setAuthLoading(false);
            }
        });
        return () => unsubscribe();
    }, []);

    const handleLogout = async () => {
        await signOut(auth);
        setUser(null);
    };
    
    const isLoading = authLoading || cryptoScriptStatus !== 'ready';

    return (
        <div className="min-h-screen bg-slate-100 font-sans">
             <style>{`
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
                body { font-family: 'Inter', sans-serif; }
                @keyframes scale-in { 0% { transform: scale(0.95); opacity: 0; } 100% { transform: scale(1); opacity: 1; } }
                .animate-scale-in { animation: scale-in 0.2s ease-out forwards; }
            `}</style>
            <nav className="bg-white/80 backdrop-blur-lg shadow-sm sticky top-0 z-40">
                <div className="container mx-auto px-6 py-4 flex justify-between items-center">
                    <h1 className="text-2xl font-bold text-violet-600">SecureShare</h1>
                    {user && (
                         <div className="flex items-center space-x-4">
                            <span className="text-slate-600 text-sm font-medium hidden sm:inline">{user.email}</span>
                            <button onClick={handleLogout} className="bg-violet-100 text-violet-700 px-4 py-2 rounded-lg hover:bg-violet-200 transition-colors font-semibold">Logout</button>
                         </div>
                    )}
                </div>
            </nav>
            <main className="container mx-auto px-6 py-8 md:py-12">
                {isLoading ? (
                     <div className="text-center py-10"><p className="text-lg font-semibold text-slate-500">Initializing SecureShare...</p></div>
                ) : !user ? (
                    <AuthComponent setUser={setUser} />
                ) : (
                     <div className="max-w-2xl mx-auto">
                        <FileUpload user={user} />
                        <FileList user={user} />
                    </div>
                )}
            </main>
             <footer className="text-center py-6 text-slate-500 text-sm">
                <p>SecureShare &copy; {new Date().getFullYear()}</p>
            </footer>
        </div>
    );
}
