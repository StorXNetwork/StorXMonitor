import { defineStore } from 'pinia';
import { developerApi, type DeveloperAccount } from '@/api/developerApi';

interface AuthState {
    isAuthenticated: boolean;
    account: DeveloperAccount | null;
    loading: boolean;
}

export const useAuthStore = defineStore('auth', {
    state: (): AuthState => ({
        isAuthenticated: false,
        account: null,
        loading: false,
    }),

    getters: {
        isResetPassStatus(): boolean {
            return this.account?.status === 6;
        },
    },

    actions: {
        async checkAuth() {
            try {
                const account = await developerApi.getAccount();
                this.account = account;
                this.isAuthenticated = true;
                return true;
            } catch {
                this.isAuthenticated = false;
                this.account = null;
                return false;
            }
        },

        async login(email: string, password: string) {
            this.loading = true;
            try {
                await developerApi.login(email, password);
                // After login, get account info
                await this.checkAuth();
                return true;
            } catch (error) {
                throw error;
            } finally {
                this.loading = false;
            }
        },

        async logout() {
            try {
                await developerApi.logout();
            } catch (error) {
                console.error('Logout error:', error);
            } finally {
                this.isAuthenticated = false;
                this.account = null;
            }
        },

        async resetPasswordWithToken(token: string, newPassword: string) {
            this.loading = true;
            try {
                await developerApi.resetPasswordWithToken(token, newPassword);
                return true;
            } catch (error) {
                throw error;
            } finally {
                this.loading = false;
            }
        },

        async resetPasswordAfterLogin(newPassword: string) {
            this.loading = true;
            try {
                await developerApi.resetPasswordAfterLogin(newPassword);
                // Refresh account info after password reset
                await this.checkAuth();
                return true;
            } catch (error) {
                throw error;
            } finally {
                this.loading = false;
            }
        },

        async updateAccount(fullName: string) {
            this.loading = true;
            try {
                await developerApi.updateAccount(fullName);
                await this.checkAuth();
            } catch (error) {
                throw error;
            } finally {
                this.loading = false;
            }
        },
    },
});

