ip_pool = new Array();

function save_proxy_setting() {
  chrome.extension.sendMessage({'cmd':'proxy='+'sound.cs.washington.edu'+':'+'8964'});
}

chrome.extension.onMessage.addListener(
  function(request, sender, sendResponse) {
      setTimeout(function() { refresh_pool();; }, 100);
  }
);


function draw_ip_pool(pool){
  if(pool.length == 0) return;

  var tar=document.getElementById("ip_pool");
  for (var zxc0=0;zxc0<1;zxc0++){
    var table=document.createElement('TABLE');
    table.id = 'ip_pool_table';
    //table[id] = 'table';
    table.border='1';
    var tbdy=document.createElement('TBODY');
    table.appendChild(tbdy);
    for (var zxc1=0;zxc1<pool.length;zxc1++){
      var tr=document.createElement('TR');
      tbdy.appendChild(tr);
      for (var zxc2=0;zxc2<2;zxc2++){
        var td=document.createElement('TD');
        td.width='100';
        if(zxc2==0)td.appendChild(document.createTextNode(pool[zxc1].ip));
        else td.appendChild(document.createTextNode(pool[zxc1].pseudonym));
        tr.appendChild(td);
      }
    }

    table_old = document.getElementById('ip_pool_table');
    if(table_old != undefined)
      table_old.parentNode.removeChild(table_old);
    }
    tar.appendChild(table);

};

function refresh_pool() {
  chrome.extension.sendMessage(
    {'cmd':'ip='+'refresh'},
    function(response){
       ip_pool = JSON.parse(response);
    }
  );
  draw_ip_pool(ip_pool);
}

function request_ip() {
  chrome.extension.sendMessage({'cmd':'ip='+'request'});
}

window.onload = function() {
  document.getElementById('save_proxy_setting').addEventListener('click', save_proxy_setting, false);
  document.getElementById('refresh_pool').addEventListener('click', refresh_pool, false);
  document.getElementById('request_ip').addEventListener('click', request_ip, false);
}






