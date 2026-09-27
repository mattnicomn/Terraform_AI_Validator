import { useAuth } from "../auth/AuthProvider";

/**
 * Account page (protected).
 *
 * Displays a minimal, safe identity from OIDC claims only (email >
 * preferred_username > "Signed in"). Never renders raw JWTs, the subject id,
 * or any access/refresh/id token. Offers Sign out.
 */
export function Account() {
  const { user, signOut } = useAuth();

  return (
    <main className="page" id="main">
      <section className="state-panel">
        <h1 className="state-panel__title">Account</h1>
        <dl className="account__list">
          <dt className="account__term">Signed in as</dt>
          <dd className="account__def">{user?.username ?? "Signed in"}</dd>
          {user?.email && (
            <>
              <dt className="account__term">Email</dt>
              <dd className="account__def">{user.email}</dd>
            </>
          )}
        </dl>
        <button
          type="button"
          className="btn btn--primary"
          onClick={() => void signOut()}
        >
          Sign out
        </button>
      </section>
    </main>
  );
}
