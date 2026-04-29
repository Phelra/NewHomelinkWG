// Tab switching (runs before main script; references globals defined later)
function switchTab(name) {
  var tabs = ['status','services','logs'];
  tabs.forEach(function(t) {
    var btn = document.getElementById('tab-btn-nav-' + t);
    var pane = document.getElementById('tab-' + t);
    if (btn) btn.classList.toggle('active', t === name);
    if (pane) pane.style.display = t === name ? '' : 'none';
  });
  // Initialise logs when tab is first opened
  if (name==='logs') { initLogs(); }
}
