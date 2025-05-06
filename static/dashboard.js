const socket = io();

  
        
        socket.on('update', function(data) {
            document.getElementById('total').textContent = data.total;
            document.getElementById('suspicious').textContent = data.suspicious;
            
            if (data.new_alert) {
                const alertEl = document.getElementById('alert');
                alertEl.textContent = 'New alert: ' + data.new_alert;
                alertEl.style.display = 'block';
                
                // Flash effect
                alertEl.style.backgroundColor = 'rgba(255,0,0,0.2)';
                setTimeout(() => {
                    alertEl.style.backgroundColor = '';
                }, 1000);
            }
        });