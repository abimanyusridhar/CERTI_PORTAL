'use strict';
(function () {
  function switchAdminTab(tab) {
    var map = { records: 'Records', users: 'Users', groups: 'Groups', docs: 'Docs' };
    Object.keys(map).forEach(function (t) {
      var pane = document.getElementById('pane' + map[t]);
      var btn  = document.getElementById('adminTabBtn' + map[t]);
      if (pane) pane.classList.toggle('active', t === tab);
      if (btn) btn.classList.toggle('active', t === tab);
    });
  }
  window.switchAdminTab = switchAdminTab;

  var requestedTab = new URLSearchParams(window.location.search).get('tab');
  if (requestedTab && ['records','users','groups','docs'].includes(requestedTab)) switchAdminTab(requestedTab);
})();
