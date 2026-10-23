import {
  InteractionRequiredAuthError,
  PublicClientApplication,
  type AccountInfo
} from "@azure/msal-browser";
import { MsalProvider, useMsal } from "@azure/msal-react";
import {
  createContext,
  type PropsWithChildren,
  useCallback,
  useContext,
  useMemo
} from "react";
import { bowerConfig } from "./runtimeConfig";

interface AuthContextValue {
  accountName: string;
  authenticated: boolean;
  development: boolean;
  getAccessToken: () => Promise<string | null>;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);
const development = bowerConfig.authMode === "development";
const tenantId = bowerConfig.entraTenantId;
const clientId = bowerConfig.entraClientId;
const apiScope = bowerConfig.entraApiScope;
const redirectUri = bowerConfig.entraRedirectUri ?? window.location.origin;

let msal: PublicClientApplication | null = null;
if (!development) {
  if (!tenantId || !clientId || !apiScope) {
    throw new Error(
      "Entra configuration is incomplete. Set tenant, client and API scope variables."
    );
  }

  msal = new PublicClientApplication({
    auth: {
      clientId,
      authority: `https://login.microsoftonline.com/${tenantId}`,
      redirectUri,
      postLogoutRedirectUri: redirectUri
    },
    cache: {
      cacheLocation: "memoryStorage"
    }
  });
}

function DevelopmentAuth({ children }: PropsWithChildren) {
  const value = useMemo<AuthContextValue>(
    () => ({
      accountName: "Local development administrator",
      authenticated: true,
      development: true,
      getAccessToken: async () => null,
      signIn: async () => undefined,
      signOut: async () => undefined
    }),
    []
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function EntraAuth({ children }: PropsWithChildren) {
  const { instance, accounts } = useMsal();
  const account: AccountInfo | undefined = instance.getActiveAccount() ?? accounts[0];
  if (account && !instance.getActiveAccount()) {
    instance.setActiveAccount(account);
  }

  const signIn = useCallback(async () => {
    const result = await instance.loginPopup({
      scopes: ["openid", "profile", apiScope]
    });
    instance.setActiveAccount(result.account);
  }, [instance]);

  const signOut = useCallback(async () => {
    await instance.logoutPopup({ account });
  }, [account, instance]);

  const getAccessToken = useCallback(async () => {
    const active = instance.getActiveAccount() ?? accounts[0];
    if (!active) {
      await signIn();
      return null;
    }

    try {
      const response = await instance.acquireTokenSilent({
        account: active,
        scopes: [apiScope]
      });
      return response.accessToken;
    } catch (error) {
      if (error instanceof InteractionRequiredAuthError) {
        const response = await instance.acquireTokenPopup({
          account: active,
          scopes: [apiScope]
        });
        return response.accessToken;
      }
      throw error;
    }
  }, [accounts, instance, signIn]);

  const value = useMemo<AuthContextValue>(
    () => ({
      accountName: account?.name ?? "",
      authenticated: Boolean(account),
      development: false,
      getAccessToken,
      signIn,
      signOut
    }),
    [account?.name, getAccessToken, signIn, signOut]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export async function initializeAuthentication(): Promise<void> {
  if (msal) {
    await msal.initialize();
  }
}

export function AuthenticationProvider({ children }: PropsWithChildren) {
  if (development) {
    return <DevelopmentAuth>{children}</DevelopmentAuth>;
  }

  return (
    <MsalProvider instance={msal!}>
      <EntraAuth>{children}</EntraAuth>
    </MsalProvider>
  );
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("AuthenticationProvider is missing.");
  }
  return value;
}
