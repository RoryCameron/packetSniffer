const socket = io();

  
        
        socket.on('update', function(data) {
            //document.getElementById('total').textContent = data.total;
            
            if (data.new_alert) {
                const alertEl = document.getElementById('alert');
                alertEl.textContent = 'Latest alert: ' + data.new_alert;
                alertEl.style.display = 'block';
                
                // Flash effect
                alertEl.style.backgroundColor = 'rgba(255,0,0,0.2)';
                setTimeout(() => {
                    alertEl.style.backgroundColor = '';
                }, 1000);
            }

            if (data.suspicious) {
                const container = document.getElementById('IPLog') || (() => {
                    const c = document.createElement('div');
                    c.id = 'susIPs-container';
                    document.body.appendChild(c);
                    return c;
                })();

                const existingIPs = new Set();
                document.querySelectorAll('.susIP').forEach(el => {
                    //existingIPs.add(el.textContent);
                    existingIPs.add(el.querySelector('h3').textContent);
                });
            
                data.suspicious.forEach(ip => {
                    if (!existingIPs.has(ip)) {
                        /*
                        const alertEl = document.createElement("div");
                        alertEl.className = "susIP";
                        alertEl.textContent = ip;
                        container.appendChild(alertEl);
                        */
                        const ipDiv = document.createElement("div");
                        ipDiv.className = "susIP";
                
                        const ipHeading = document.createElement("h3");
                        ipHeading.textContent = ip;
                        
                        ipDiv.appendChild(ipHeading);
                        container.appendChild(ipDiv);

                        // Flash effect
                        //alertEl.style.backgroundColor = 'rgba(0, 30, 255, 0.2)';
                        setTimeout(() => {
                            //alertEl.style.backgroundColor = '';
                        }, 1000);
            
                        // Add to our tracking set
                        existingIPs.add(ip);
                    }
                });
            }
        });