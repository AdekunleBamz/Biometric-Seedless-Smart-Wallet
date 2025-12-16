import React, { useState, useEffect } from 'react';
import { AppConfig, UserSession, showConnect } from '@stacks/connect';

// Configure the app with permissions
const appConfig = new AppConfig(['store_write', 'publish_data']);
// Create a UserSession object
export const userSession = new UserSession({ appConfig });

const ConnectWallet = () => {
    const [userData, setUserData] = useState<any>(null);

    const handleConnect = () => {
        showConnect({
            appDetails: {
                name: 'Biometric Smart Wallet',
                icon: window.location.origin + '/vite.svg',
            },
            redirectTo: '/',
            onFinish: () => {
                const userData = userSession.loadUserData();
                setUserData(userData);
            },
            userSession: userSession,
        });
    };

    const handleSignOut = () => {
        userSession.signUserOut();
        setUserData(null);
    };

    useEffect(() => {
        if (userSession.isUserSignedIn()) {
            setUserData(userSession.loadUserData());
        }
    }, []);

    return (
        <div style={{ padding: '20px', border: '1px solid #ccc', borderRadius: '8px', marginBottom: '20px' }}>
            <h2>Stacks Wallet Connection</h2>
            {!userData ? (
                <button
                    onClick={handleConnect}
                    style={{ padding: '10px 20px', fontSize: '16px', cursor: 'pointer' }}
                >
                    Connect Wallet
                </button>
            ) : (
                <div>
                    <p><strong>Status:</strong> Connected</p>
                    <p><strong>Address (Testnet):</strong> {userData.profile.stxAddress.testnet}</p>
                    <p><strong>Address (Mainnet):</strong> {userData.profile.stxAddress.mainnet}</p>
                    <button
                        onClick={handleSignOut}
                        style={{ padding: '8px 16px', fontSize: '14px', cursor: 'pointer', marginTop: '10px' }}
                    >
                        Sign Out
                    </button>
                </div>
            )}
        </div>
    );
};

export default ConnectWallet;
