'use client';

import React from 'react';
import type { PasskeyModalConfig } from '../../types/modal';

interface PasskeyModalProps {
    isOpen: boolean;
    onCreatePasskey: () => void;
    config?: PasskeyModalConfig;
}

export function PasskeyModal({ isOpen, onCreatePasskey, config = {} }: PasskeyModalProps) {
    if (!isOpen) return null;

    const {
        message = 'Create a passkey to continue',
        backgroundColor = '#FFFFFF',
        textColor = '#000000',
        showBranding = true,
        buttonText = 'Create Passkey',
        buttonBackgroundColor = '#000000',
        buttonTextColor = '#FFFFFF',
    } = config;

    return (
        <>
            {/* Google Fonts - Geist */}
            <link
                href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&display=swap"
                rel="stylesheet"
            />

            {/* Responsive Styles */}
            <style>
                {`
                    .cavos-modal-container {
                        padding: 48px 24px 24px;
                    }
                    .cavos-modal-button {
                        width: 50%;
                    }
                    @media (max-width: 480px) {
                        .cavos-modal-container {
                            padding: 32px 20px 20px !important;
                        }
                        .cavos-modal-button {
                            width: 100% !important;
                        }
                    }
                `}
            </style>

            {/* Modal Overlay */}
            <div
                style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    backgroundColor: 'rgba(0, 0, 0, 0.5)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 9999,
                    fontFamily: 'Geist, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
                }}
            >
                {/* Modal Content */}
                <div
                    className="cavos-modal-container"
                    style={{
                        backgroundColor,
                        borderRadius: '24px',
                        maxWidth: '500px',
                        width: '90%',
                        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)',
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        gap: '24px',
                    }}
                >
                    {/* Message */}
                    <h2
                        style={{
                            fontSize: '18px',
                            fontWeight: '500',
                            color: textColor,
                            margin: 0,
                            textAlign: 'center',
                            lineHeight: '1.4',
                        }}
                    >
                        {message}
                    </h2>

                    {/* Fingerprint Icon */}
                    <div
                        style={{
                            width: '50px',
                            height: '50px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                        }}
                    >
                        <svg
                            width="80"
                            height="80"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke={textColor}
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                        >
                            <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
                            <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
                            <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
                            <path d="M2 12a10 10 0 0 1 18-6" />
                            <path d="M2 16h.01" />
                            <path d="M21.8 16c.2-2 .131-5.354 0-6" />
                            <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
                            <path d="M8.65 22c.21-.66.45-1.32.57-2" />
                            <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
                        </svg>
                    </div>

                    {/* Create Button */}
                    <button
                        className="cavos-modal-button"
                        onClick={onCreatePasskey}
                        style={{
                            backgroundColor: buttonBackgroundColor,
                            color: buttonTextColor,
                            border: 'none',
                            borderRadius: '12px',
                            padding: '10px 24px',
                            fontSize: '14px',
                            fontWeight: '400',
                            cursor: 'pointer',
                            fontFamily: 'inherit',
                            transition: 'opacity 0.2s',
                        }}
                        onMouseEnter={(e) => {
                            e.currentTarget.style.opacity = '0.9';
                        }}
                        onMouseLeave={(e) => {
                            e.currentTarget.style.opacity = '1';
                        }}
                    >
                        {buttonText}
                    </button>

                    {/* Branding */}
                    {showBranding && (
                        <div
                            style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                opacity: 0.8,
                            }}
                        >
                            <span
                                style={{
                                    fontSize: '14px',
                                    color: '#666666',
                                    fontWeight: '500',
                                }}
                            >
                                powered by
                            </span>
                            <img
                                src="data:image/png;base64,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"
                                alt="Cavos"
                                style={{
                                    height: '24px',
                                    width: 'auto',
                                    opacity: 0.9,
                                }}
                            />
                        </div>
                    )}
                </div>
            </div>
        </>
    );
}
