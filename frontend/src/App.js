// frontend/src/App.js
import React, { useState, useEffect } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  Navigate,
  useNavigate,
} from "react-router-dom";
import axios from "axios";

const API_BASE = "http://127.0.0.1:8000/api";

function App() {
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [role, setRole] = useState(localStorage.getItem("role") || "");
  const [uid, setUid] = useState(localStorage.getItem("uid") || "");

  const logout = () => {
    localStorage.clear();
    setToken("");
    setRole("");
    setUid("");
  };

  return (
    <Router>
      <div className="p-4">
        <nav className="flex gap-4 mb-4">
          <Link to="/">Home</Link>
          {!token && <Link to="/login">Login</Link>}
          {!token && <Link to="/register">Register</Link>}
          {token && <Link to="/my">My Registrations</Link>}
          {role === "ADMIN" && <Link to="/admin">Admin</Link>}
          {token && (
            <button onClick={logout} className="ml-auto">
              Logout
            </button>
          )}
        </nav>

        <Routes>
          <Route path="/" element={<Home />} />
          <Route
            path="/login"
            element={<Login setToken={setToken} setRole={setRole} setUid={setUid} />}
          />
          <Route path="/register" element={<Register />} />
          <Route path="/team/:sport" element={<TeamRegister token={token} />} />
          <Route path="/individual/:sport" element={<IndividualRegister token={token} />} />
          <Route path="/my" element={token ? <MyRegistrations token={token} /> : <Navigate to="/login" />} />
          <Route path="/admin" element={role === "ADMIN" ? <Admin token={token} /> : <Navigate to="/" />} />
        </Routes>
      </div>
    </Router>
  );
}

function Home() {
  return <h2>🏆 Welcome to Indus Cup</h2>;
}

// ==================== Auth ====================
function Register() {
  const [form, setForm] = useState({});
  const [msg, setMsg] = useState("");

  const submit = async () => {
    try {
      const res = await axios.post(`${API_BASE}/public/register`, form);
      setMsg(res.data.message + " Your Uid: " + res.data.Uid);
    } catch (err) {
      setMsg("Error: " + err.response?.data?.detail);
    }
  };

  return (
    <div>
      <h2>User Register</h2>
      {["First_Name", "Last_Name", "collage_name", "Collage_id", "Cont_no", "Email", "password"].map((f) => (
        <input
          key={f}
          placeholder={f}
          onChange={(e) => setForm({ ...form, [f]: e.target.value })}
        />
      ))}
      <button onClick={submit}>Register</button>
      <p>{msg}</p>
    </div>
  );
}

function Login({ setToken, setRole, setUid }) {
  const [Uid, setU] = useState("");
  const [password, setP] = useState("");
  const [msg, setMsg] = useState("");
  const navigate = useNavigate();

  const submit = async () => {
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, { Uid, password });
      localStorage.setItem("token", res.data.access_token);
      localStorage.setItem("role", res.data.role);
      localStorage.setItem("uid", res.data.Uid);
      setToken(res.data.access_token);
      setRole(res.data.role);
      setUid(res.data.Uid);
      navigate("/");
    } catch (err) {
      setMsg("Login failed");
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <input placeholder="Uid" value={Uid} onChange={(e) => setU(e.target.value)} />
      <input placeholder="Password" type="password" value={password} onChange={(e) => setP(e.target.value)} />
      <button onClick={submit}>Login</button>
      <p>{msg}</p>
    </div>
  );
}

// ==================== Team Register ====================
function TeamRegister({ token }) {
  const [sport, setSport] = useState("cricket");
  const [teamNo, setTeamNo] = useState("");
  const [college, setCollege] = useState("");
  const [captain, setCaptain] = useState({});
  const [vice, setVice] = useState({});
  const [msg, setMsg] = useState("");

  const submit = async () => {
    try {
      const form = new FormData();
      form.append("Team_no", teamNo);
      form.append("collage_name", college);
      form.append("captain", JSON.stringify(captain));
      form.append("vice", JSON.stringify(vice));
      const res = await axios.post(`${API_BASE}/team/${sport}/register`, form, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMsg("Registered! Team_id: " + res.data.Team_id + " (Pay via Razorpay)");
    } catch (err) {
      setMsg("Error: " + err.response?.data?.detail);
    }
  };

  return (
    <div>
      <h2>Team Register</h2>
      <select value={sport} onChange={(e) => setSport(e.target.value)}>
        <option value="cricket">Cricket</option>
        <option value="football">Football</option>
        <option value="basketball">Basketball</option>
      </select>
      <input placeholder="Team No" onChange={(e) => setTeamNo(e.target.value)} />
      <input placeholder="College" onChange={(e) => setCollege(e.target.value)} />
      <input placeholder="Captain Name" onChange={(e) => setCaptain({ ...captain, name: e.target.value })} />
      <input placeholder="Vice Name" onChange={(e) => setVice({ ...vice, name: e.target.value })} />
      <button onClick={submit}>Register Team</button>
      <p>{msg}</p>
    </div>
  );
}

// ==================== Individual Register ====================
function IndividualRegister({ token }) {
  const [sport, setSport] = useState("badminton");
  const [form, setForm] = useState({});
  const [msg, setMsg] = useState("");

  const submit = async () => {
    try {
      const fd = new FormData();
      Object.entries(form).forEach(([k, v]) => fd.append(k, v));
      const res = await axios.post(`${API_BASE}/individual/${sport}/register`, fd, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMsg("Registered! Player_id: " + res.data.player_id + " (Pay via Razorpay)");
    } catch (err) {
      setMsg("Error: " + err.response?.data?.detail);
    }
  };

  return (
    <div>
      <h2>Individual Register</h2>
      <select value={sport} onChange={(e) => setSport(e.target.value)}>
        <option value="badminton">Badminton</option>
        <option value="chess">Chess</option>
      </select>
      {["player_no", "collage_name", "name", "number", "email", "Collage_id", "Collage_id_img"].map((f) => (
        <input key={f} placeholder={f} onChange={(e) => setForm({ ...form, [f]: e.target.value })} />
      ))}
      <button onClick={submit}>Register</button>
      <p>{msg}</p>
    </div>
  );
}

// ==================== My Registrations ====================
function MyRegistrations({ token }) {
  const [data, setData] = useState([]);

  useEffect(() => {
    axios
      .get(`${API_BASE}/my_registrations`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => setData(res.data.data));
  }, [token]);

  return (
    <div>
      <h2>My Registrations</h2>
      <ul>
        {data.map((r, i) => (
          <li key={i}>
            {r.type} {r.sport} – {r.status}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ==================== Admin ====================
function Admin({ token }) {
  const [data, setData] = useState({});

  useEffect(() => {
    axios
      .get(`${API_BASE}/admin/registrations`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => setData(res.data.data));
  }, [token]);

  return (
    <div>
      <h2>Admin Panel</h2>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
}

export default App;
