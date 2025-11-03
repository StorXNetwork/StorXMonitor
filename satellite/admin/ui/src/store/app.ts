// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

import { reactive } from "vue";
import { defineStore } from "pinia";

import {
  PlacementInfo,
  Project,
  ProjectLimitsUpdate,
  ProjectManagementHttpApiV1,
  UserAccount,
  Settings,
} from "@/api/client.gen";
import { AdminHttpClient } from "@/utils/adminHttpClient";

class AppState {
  public placements: PlacementInfo[];
  public userAccount: UserAccount | null = null;
  public selectedProject: Project | null = null;
  public settings: Settings | null = null; // Initialize as null to handle race conditions
}

export const useAppStore = defineStore("app", () => {
  const state = reactive<AppState>(new AppState());

  const projectApi = new ProjectManagementHttpApiV1();
  const httpClient = new AdminHttpClient();

  async function getUserByEmail(email: string): Promise<void> {
    const response = await httpClient.get(`/api/users/${encodeURIComponent(email)}`);
    if (!response.ok) {
      if (response.status === 404) {
        const error = new Error(`User with email ${email} does not exist`);
        (error as any).responseStatusCode = 404;
        throw error;
      }
      throw new Error(`Failed to get user: ${response.statusText}`);
    }
    
    const data = await response.json();
    // Map the response from { user: {...}, projects: [...] } to UserAccount format
    state.userAccount = {
      id: data.user.id,
      fullName: data.user.fullName,
      email: data.user.email,
      paidTier: data.user.paidTier,
      createdAt: '', // Not returned by endpoint
      status: '', // Not returned by endpoint
      userAgent: '', // Not returned by endpoint
      defaultPlacement: data.user.placement,
      projectLimit: data.user.projectLimit,
      projects: data.projects?.map((p: any) => ({
        id: p.id,
        name: p.name,
        bandwidthLimit: p.bandwidthLimit || 0,
        bandwidthUsed: p.bandwidthUsed || 0,
        storageLimit: p.storageLimit || 0,
        storageUsed: p.storageUsed || null,
        segmentLimit: p.segmentLimit || 0,
      })) || null,
    } as UserAccount;
  }

  function clearUser(): void {
    state.userAccount = null;
  }

  async function getPlacements(): Promise<void> {
    const response = await httpClient.get("/api/placements");
    if (!response.ok) {
      throw new Error(`Failed to get placements: ${response.statusText}`);
    }
    state.placements = await response.json();
  }

  function getPlacementText(code: number): string {
    for (const placement of state.placements) {
      if (placement.id === code) {
        if (placement.location) {
          return placement.location;
        }
        break;
      }
    }
    return `Unknown (${code})`;
  }

  async function selectProject(id: string): Promise<void> {
    state.selectedProject = await projectApi.getProject(id);
  }

  async function updateProjectLimits(
    id: string,
    limits: ProjectLimitsUpdate,
  ): Promise<void> {
    await projectApi.updateProjectLimits(limits, id);
    if (state.selectedProject && state.selectedProject.id === id) {
      state.selectedProject.maxBuckets = limits.maxBuckets;
      state.selectedProject.storageLimit = limits.storageLimit;
      state.selectedProject.bandwidthLimit = limits.bandwidthLimit;
      state.selectedProject.segmentLimit = limits.segmentLimit;
      state.selectedProject.rateLimit = limits.rateLimit;
      state.selectedProject.burstLimit = limits.burstLimit;
    }
    if (state.userAccount && state.userAccount.projects) {
      const updatedData = {
        storageLimit: limits.storageLimit,
        bandwidthLimit: limits.bandwidthLimit,
        segmentLimit: limits.segmentLimit,
      };
      state.userAccount.projects.map((item) =>
        item.id === id ? { ...item, updatedData } : item,
      );
    }
  }

  async function getSettings(): Promise<void> {
    const response = await httpClient.get("/api/settings");
    if (!response.ok) {
      throw new Error(`Failed to get settings: ${response.statusText}`);
    }
    state.settings = await response.json();
  }

  return {
    state,
    getUserByEmail,
    clearUser,
    getPlacements,
    getPlacementText,
    selectProject,
    updateProjectLimits,
    getSettings,
  };
});
