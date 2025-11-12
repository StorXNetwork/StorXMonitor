/**
 * Validation utility functions
 */

export function validateEmail(email: string): boolean {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

export function validatePassword(password: string): { valid: boolean; message?: string } {
    if (password.length < 8) {
        return { valid: false, message: 'Password must be at least 8 characters long' };
    }
    return { valid: true };
}

export function validatePasswordMatch(password: string, confirmPassword: string): boolean {
    return password === confirmPassword;
}

