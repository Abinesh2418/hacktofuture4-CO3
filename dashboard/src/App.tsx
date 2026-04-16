import { Routes, Route, Navigate } from "react-router-dom";
import { useState, createContext, useContext } from "react";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { MfaSetupPage } from "./pages/MfaSetupPage";
import { ArenaDashboard } from "./pages/ArenaDashboard";

interface AuthState {
  token: string | null;
  username: string | null;
  login: (token: string, username: string) => void;
  logout: () => void;
}

export const AuthContext = createContext<AuthState>({
  token: null, username: null,
  login: () => {}, logout: () => {},
});

export const useAuth = () => useContext(AuthContext);

export function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem("htf_token"));
  const [username, setUsername] = useState<string | null>(localStorage.getItem("htf_user"));

  const login = (t: string, u: string) => {
    setToken(t); setUsername(u);
    localStorage.setItem("htf_token", t);
    localStorage.setItem("htf_user", u);
  };
  const logout = () => {
    setToken(null); setUsername(null);
    localStorage.removeItem("htf_token");
    localStorage.removeItem("htf_user");
  };

  return (
    <AuthContext.Provider value={{ token, username, login, logout }}>
      <Routes>
        <Route path="/login" element={token ? <Navigate to="/arena" /> : <LoginPage />} />
        <Route path="/register" element={token ? <Navigate to="/arena" /> : <RegisterPage />} />
        <Route path="/mfa-setup" element={<MfaSetupPage />} />
        <Route path="/arena" element={token ? <ArenaDashboard /> : <Navigate to="/login" />} />
        <Route path="*" element={<Navigate to={token ? "/arena" : "/login"} />} />
      </Routes>
    </AuthContext.Provider>
  );
}
