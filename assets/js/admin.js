jQuery(document).ready(function($) {
    function updateDashboard(callback) {
        console.log('Updating dashboard...');
        $.ajax({
            url: wpSecurityCheck.ajax_url,
            type: 'POST',
            data: {
                action: 'get_security_status',
                nonce: wpSecurityCheck.nonce
            },
            dataType: 'json',
            success: function(response) {
                if (response && response.success && response.data) {
                    if (response.data.score !== undefined) {
                        updateSecurityScoreChart(response.data.score);
                    }
                    if (response.data.checks) {
                        updateSecurityChecksTable(response.data.checks);
                    }
                    if (callback && typeof callback === 'function') {
                        callback();
                    }
                } else {
                    console.error('Invalid response format', response);
                    if (callback && typeof callback === 'function') {
                        callback();
                    }
                }
            },
            error: function(xhr, status, error) {
                console.error('AJAX error:', status, error);
                alert('Ein Fehler ist aufgetreten beim Aktualisieren des Dashboards. Bitte versuchen Sie es erneut.');
                if (callback && typeof callback === 'function') {
                    callback();
                }
            }
        });
    }

    function displaySecurityResults(data) {
        if (data.score !== undefined) {
            updateSecurityScoreChart(data.score);
        } else {
            console.error('Score not found in response data');
            updateSecurityScoreChart(0);
        }
        if (data.checks) {
            updateSecurityChecksTable(data.checks);
        } else {
            console.error('Checks not found in response data');
        }
    }

    function loadLastSecurityCheck() {
        $.ajax({
            url: wpSecurityCheck.ajax_url,
            type: 'POST',
            data: {
                action: 'get_last_security_check',
                nonce: wpSecurityCheck.nonce
            },
            dataType: 'json',
            success: function(response) {
                if (response && response.success && response.data) {
                    // Speichern Sie die Daten, aber zeigen Sie sie nicht sofort an
                    window.lastSecurityCheck = response.data;
                } else {
                    console.log('No previous security check results found');
                    window.lastSecurityCheck = null;
                }
                // Zeigen Sie eine Aufforderung an, die Prüfung durchzuführen
                $('#security-checks-table').html('<p>Klicken Sie auf "Sicherheitsprüfungen durchführen", um eine neue Prüfung zu starten oder die letzten Ergebnisse anzuzeigen.</p>');
            },
            error: function(xhr, status, error) {
                console.error('Error loading last security check:', error);
            }
        });
    }

    function updateSecurityScoreChart(score) {
        console.log('Updating security score chart with score:', score);
        var ctx = document.getElementById('security-score-chart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: ['#4CAF50', '#F44336']
                }],
                labels: ['Sicher', 'Verbesserungswürdig']
            },
            options: {
                responsive: true,
                title: {
                    display: true,
                    text: 'Sicherheitsbewertung: ' + score + '%'
                }
            }
        });
    }

    function updateSecurityChecksTable(checks) {
        var tableHtml = '<table><tr><th>Prüfung</th><th>Status</th><th>Nachricht</th></tr>';
        for (var key in checks) {
            var statusClass = checks[key].status ? 'security-status-good' : 'security-status-bad';
            var statusText = checks[key].status ? 'Gut' : 'Verbesserungswürdig';
            tableHtml += '<tr><td>' + key + '</td><td class="' + statusClass + '">' + statusText + '</td><td>' + checks[key].message + '</td></tr>';
        }
        tableHtml += '</table>';
        $('#security-checks-table').html(tableHtml);
    }

    $('#run-security-checks').on('click', function() {
        var $button = $(this);
        var $loadingMessage = $('<p>').text('Sicherheitsprüfung läuft. Bitte warten...').insertAfter($button);
        
        $button.prop('disabled', true);
    
        // Führen Sie zuerst die Sicherheitsprüfungen durch
        $.ajax({
            url: wpSecurityCheck.ajax_url,
            type: 'POST',
            data: {
                action: 'run_security_checks',
                nonce: wpSecurityCheck.nonce
            },
            success: function(response) {
                // Nach erfolgreicher Durchführung der Prüfungen, aktualisieren Sie das Dashboard
                updateDashboard(function() {
                    // Callback-Funktion, die nach der Dashboard-Aktualisierung ausgeführt wird
                    $loadingMessage.remove();
                    alert('Sicherheitsprüfungen abgeschlossen.');
                    $button.prop('disabled', false).text('Sicherheitsprüfungen durchführen');
                });
            },
            error: function() {
                $loadingMessage.remove();
                alert('Ein Fehler ist aufgetreten bei den Sicherheitsprüfungen. Bitte versuchen Sie es erneut.');
                $button.prop('disabled', false).text('Sicherheitsprüfungen durchführen');
            }
        });
    });

    $('#create-backup').on('click', function() {
        if (confirm('Möchten Sie wirklich ein Backup erstellen? Dies kann einige Zeit in Anspruch nehmen.')) {
            var $button = $(this);
            var $result = $('#backup-result');

            $button.prop('disabled', true).text('Backup wird erstellt...');
            $result.html('');

            $.ajax({
                url: wpSecurityCheck.ajax_url,
                type: 'POST',
                data: {
                    action: 'create_backup',
                    nonce: wpSecurityCheck.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $result.html('<p class="security-status-good">' + response.data.message + '</p>');
                        if (response.data.file) {
                            $result.append('<p>Backup-Datei: ' + response.data.file + '</p>');
                        }
                    } else {
                        $result.html('<p class="security-status-bad">Fehler: ' + response.data.message + '</p>');
                    }
                },
                error: function() {
                    $result.html('<p class="security-status-bad">Ein Fehler ist aufgetreten beim Backup-Erstellen. Bitte versuchen Sie es erneut.</p>');
                },
                complete: function() {
                    $button.prop('disabled', false).text('Backup erstellen');
                }
            });
        }
    });

    $('#optimize-database').on('click', function() {
        if (confirm('Möchten Sie wirklich die Datenbank optimieren? Dies kann einige Zeit in Anspruch nehmen.')) {
            var $button = $(this);
            var $result = $('#optimize-result');

            $button.prop('disabled', true).text('Optimierung läuft...');
            $result.html('');

            $.ajax({
                url: wpSecurityCheck.ajax_url,
                type: 'POST',
                data: {
                    action: 'optimize_database',
                    nonce: wpSecurityCheck.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $result.html('<p class="security-status-good">' + response.data.message + '</p>');
                        if (response.data.tables) {
                            $result.append('<p>Optimierte Tabellen: ' + response.data.tables + '</p>');
                        }
                    } else {
                        $result.html('<p class="security-status-bad">Fehler: ' + response.data.message + '</p>');
                    }
                },
                error: function() {
                    $result.html('<p class="security-status-bad">Ein Fehler ist aufgetreten bei der Datenbankoptimierung. Bitte versuchen Sie es erneut.</p>');
                },
                complete: function() {
                    $button.prop('disabled', false).text('Datenbank optimieren');
                }
            });
        }
    });

    loadLastSecurityCheck();
    //updateDashboard();
});