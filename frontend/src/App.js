import logo from './logo.svg';
import './App.css';
import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Verified from './components/Verified';

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/react/email-verified" element={<Verified />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
