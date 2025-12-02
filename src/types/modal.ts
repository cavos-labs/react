/**
 * Passkey Modal Configuration Types
 */

export interface PasskeyModalConfig {
    /** Custom message to display (default: "Create a passkey to continue") */
    message?: string;
    /** Background color (default: "#FFFFFF") */
    backgroundColor?: string;
    /** Text color (default: "#000000") */
    textColor?: string;
    /** Show Cavos branding (default: true) */
    showBranding?: boolean;
    /** Custom button text (default: "Create Passkey") */
    buttonText?: string;
    /** Button background color (default: "#000000") */
    buttonBackgroundColor?: string;
    /** Button text color (default: "#FFFFFF") */
    buttonTextColor?: string;
}
