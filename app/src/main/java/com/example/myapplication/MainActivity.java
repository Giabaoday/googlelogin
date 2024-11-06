package com.example.myapplication;

import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.ComponentActivity;
import androidx.annotation.NonNull;
import androidx.credentials.CredentialManager;
import androidx.credentials.CredentialManagerCallback;
import androidx.credentials.CustomCredential;
import androidx.credentials.GetCredentialRequest;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.exceptions.GetCredentialException;

import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInClient;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.libraries.identity.googleid.GetGoogleIdOption;
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential;
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException;

import java.security.SecureRandom;

public class MainActivity extends ComponentActivity {
    private static final String TAG = "MainActivity";
    // Replace with your Web Client ID from Google Cloud Console
    private static final String WEB_CLIENT_ID = "378423130551-5knlk4hpg305j6hvbh4pkedrilno8b15.apps.googleusercontent.com";

    private CredentialManager credentialManager;
    private Button signInButton;
    private TextView statusText;
    private GoogleSignInClient mGoogleSignInClient;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        setupGoogleSignIn();

        credentialManager = CredentialManager.create(this);
        signInButton = findViewById(R.id.signInButton);
        Button signOutButton = findViewById(R.id.signOutButton);
        statusText = findViewById(R.id.statusText);

        signInButton.setOnClickListener(v -> startGoogleSignIn());
        signOutButton.setOnClickListener(v -> signOut());
    }

    private void startGoogleSignIn() {
        GetGoogleIdOption googleIdOption = new GetGoogleIdOption.Builder()
                .setFilterByAuthorizedAccounts(false)
                .setServerClientId(WEB_CLIENT_ID)
                .setNonce(generateNonce()) // Optional: Add a nonce for additional security
                .build();

        GetCredentialRequest request = new GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            credentialManager.getCredentialAsync(
                    this,
                    request,
                    null,
                    getMainExecutor(),
                    new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                        @Override
                        public void onResult(GetCredentialResponse result) {
                            handleSignIn(result);
                        }

                        @Override
                        public void onError(@NonNull GetCredentialException e) {
                            Log.e(TAG, "Error getting credential", e);
                            statusText.setText("Sign in failed: " + e.getMessage());
                        }
                    });
        }
    }

    private String generateNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return Base64.encodeToString(nonce, Base64.DEFAULT);
    }

    private void setupGoogleSignIn() {
        GoogleSignInOptions gso = new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
                .requestIdToken(WEB_CLIENT_ID)
                .requestEmail()
                .build();
        mGoogleSignInClient = GoogleSignIn.getClient(this, gso);
    }

    private void signOut() {
        mGoogleSignInClient.signOut()
                .addOnCompleteListener(this, task -> {
                    statusText.setText("Signed out");
                    // Force người dùng phải chọn tài khoản lại
                    GoogleSignIn.getClient(this,
                            new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN).build()
                    ).revokeAccess();
                });
    }

    private void handleSignIn(GetCredentialResponse result) {
        if (result == null || result.getCredential() == null) {
            statusText.setText("No credential received");
            return;
        }

        if (result.getCredential() instanceof CustomCredential) {
            CustomCredential credential = (CustomCredential) result.getCredential();

            if (GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL.equals(credential.getType())) {
                GoogleIdTokenCredential googleIdTokenCredential =
                        GoogleIdTokenCredential.createFrom(credential.getData());

                // Get the ID token
                String idToken = googleIdTokenCredential.getIdToken();

                // Get user info
                String displayName = googleIdTokenCredential.getDisplayName();
                String profilePictureUri =
                        googleIdTokenCredential.getProfilePictureUri() != null ?
                                googleIdTokenCredential.getProfilePictureUri().toString() : "";

                String userInfo = String.format(
                        "Signed in successfully!\nName: %s\nToken: %s",
                        displayName,
                        idToken
                );
                Log.d("",idToken);
                statusText.setText(userInfo);

                // TODO: Send idToken to your backend server for verification

            }
        } else {
            Log.e(TAG, "Unexpected credential type");
            statusText.setText("Unexpected credential type");
        }
    }
}