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

interface AuthContextValue {
  accountName: string;
  authenticated: boolean;
  development: boolean;
  getAccessToken: () => Promise<string | null>;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);
const development = import.meta.env.VITE_BOWER_AUTH_MODE === "development";
const tenantId = import.meta.env.VITE_BOWER_ENTRA_TENANT_ID ?? "";
const clientId = import.meta.env.VITE_BOWER_ENTRA_CLIENT_ID ?? "";
const apiScope = import.meta.env.VITE_BOWER_ENTRA_API_SCOPE ?? "";
const redirectUri = import.meta.env.VITE_BOWER_ENTRA_REDIRECT_URI ?? window.location.origin;

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
      cacheLocation: "sessionStorage"
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
    await instance.loginRedirect({
      scopes: ["openid", "profile", apiScope]
    });
  }, [instance]);

  const signOut = useCallback(async () => {
    await instance.logoutRedirect({ account });
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
        await instance.acquireTokenRedirect({
          account: active,
          scopes: [apiScope]
        });
        return null;
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
    const result = await msal.handleRedirectPromise();
    if (result?.account) {
      msal.setActiveAccount(result.account);
    } else {
      const account = msal.getAllAccounts()[0];
      if (account) {
        msal.setActiveAccount(account);
      }
    }
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
