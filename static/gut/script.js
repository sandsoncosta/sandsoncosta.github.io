        // Initialize activities array from localStorage or empty array
        let activities = JSON.parse(localStorage.getItem('gut-activities')) || [];

        // DOM Elements
        const activityForm = document.getElementById('activity-form');
        const descriptionInput = document.getElementById('description');
        const justificationInput = document.getElementById('justification');
        const gravityInput = document.getElementById('gravity');
        const urgencyInput = document.getElementById('urgency');
        const tendencyInput = document.getElementById('tendency');
        const activitiesTableBody = document.getElementById('activities-table-body');
        const clearFormButton = document.getElementById('clear-form');
        const clearAllButton = document.getElementById('clear-all');
        const exportCsvButton = document.getElementById('export-csv');
        const showHelpButton = document.getElementById('show-help');
        const loadExamplesButton = document.getElementById('load-examples');
        const helpModal = document.getElementById('help-modal');
        const closeModalBtn = document.querySelector('.close');

        // Event Listeners
        activityForm.addEventListener('submit', addActivity);
        clearFormButton.addEventListener('click', clearForm);
        clearAllButton.addEventListener('click', clearAll);
        exportCsvButton.addEventListener('click', exportToCSV);
        showHelpButton.addEventListener('click', () => helpModal.style.display = 'block');
        closeModalBtn.addEventListener('click', () => helpModal.style.display = 'none');
        loadExamplesButton.addEventListener('click', loadExampleData);

        // Close modal when clicking outside content
        window.addEventListener('click', (event) => {
            if (event.target === helpModal) {
                helpModal.style.display = 'none';
            }
        });

        // Set up table header sort functionality
        document.querySelectorAll('#gut-table th').forEach(th => {
            th.addEventListener('click', () => {
                const sortKey = th.getAttribute('data-sort');
                if (sortKey === 'none') return;
                sortActivities(sortKey);
            });
        });

        // Functions
        function addActivity(e) {
            e.preventDefault();
            
            // Get values from form
            const description = descriptionInput.value.trim();
            const justification = justificationInput.value.trim();
            const gravity = parseInt(gravityInput.value);
            const urgency = parseInt(urgencyInput.value);
            const tendency = parseInt(tendencyInput.value);
            
            // Calculate GUT score
            const gut = gravity * urgency * tendency;
            
            // Create new activity object
            const newActivity = {
                id: Date.now(), // Unique ID based on timestamp
                description,
                justification,
                gravity,
                urgency,
                tendency,
                gut
            };
            
            // Add to activities array
            activities.push(newActivity);
            
            // Save to localStorage
            saveToLocalStorage();
            
            // Clear form
            clearForm();
            
            // Update the table
            renderActivities();
        }

        function renderActivities() {
            // Sort activities by GUT score (highest first)
            activities.sort((a, b) => b.gut - a.gut);
            
            // Clear the table body
            activitiesTableBody.innerHTML = '';
            
            // Add each activity to the table
            activities.forEach(activity => {
                const row = document.createElement('tr');
                
                // Set background color based on priority
                if (activity.gut >= 60) {
                    row.style.backgroundColor = '#ffebee'; // Light red for critical
                } else if (activity.gut >= 30) {
                    row.style.backgroundColor = '#fff8e1'; // Light yellow for medium
                }
                
                row.innerHTML = `
                    <td>${activity.description}</td>
                    <td class="number-cell">${activity.gravity}</td>
                    <td class="number-cell">${activity.urgency}</td>
                    <td class="number-cell">${activity.tendency}</td>
                    <td class="score-cell">${activity.gut}</td>
                    <td>${activity.justification || '-'}</td>
                    <td class="actions">
                        <button class="btn-danger" onclick="deleteActivity(${activity.id})">Excluir</button>
                        <button class="btn-primary" onclick="editActivity(${activity.id})">Editar</button>
                    </td>
                `;
                
                activitiesTableBody.appendChild(row);
            });
        }

        function clearForm() {
            activityForm.reset();
        }

        function clearAll() {
            if (confirm('Tem certeza que deseja remover todas as atividades?')) {
                activities = [];
                saveToLocalStorage();
                renderActivities();
            }
        }

        function deleteActivity(id) {
            activities = activities.filter(activity => activity.id !== id);
            saveToLocalStorage();
            renderActivities();
        }

        function editActivity(id) {
            const activity = activities.find(activity => activity.id === id);
            
            if (activity) {
                // Fill the form with the activity data
                descriptionInput.value = activity.description;
                justificationInput.value = activity.justification || '';
                gravityInput.value = activity.gravity;
                urgencyInput.value = activity.urgency;
                tendencyInput.value = activity.tendency;
                
                // Remove the activity from the array
                activities = activities.filter(a => a.id !== id);
                
                // Save to localStorage
                saveToLocalStorage();
                
                // Update the table
                renderActivities();
                
                // Focus on the description input
                descriptionInput.focus();
            }
        }

        function sortActivities(key) {
            // Sort the activities based on the key
            activities.sort((a, b) => {
                if (key === 'description') {
                    return a[key].localeCompare(b[key]);
                } else {
                    return b[key] - a[key]; // Descending order for numbers
                }
            });
            
            // Update the table
            renderActivities();
        }

        function saveToLocalStorage() {
            localStorage.setItem('gut-activities', JSON.stringify(activities));
        }

        function exportToCSV() {
            // Define column headers
            const headers = ['Atividade', 'G', 'U', 'T', 'GUT', 'Justificativa'];
            
            // Create CSV rows
            let csvRows = [headers.join(',')];
            
            activities.forEach(activity => {
                const row = [
                    `"${activity.description.replace(/"/g, '""')}"`, // Escape quotes
                    activity.gravity,
                    activity.urgency,
                    activity.tendency,
                    activity.gut,
                    `"${(activity.justification || '').replace(/"/g, '""')}"` // Escape quotes
                ];
                csvRows.push(row.join(','));
            });
            
            // Combine into CSV content
            const csvContent = csvRows.join('\n');
            
            // Create a download link
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.setAttribute('href', url);
            link.setAttribute('download', 'matriz_gut_' + new Date().toISOString().slice(0, 10) + '.csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        function loadExampleData() {
            if (activities.length > 0) {
                if (!confirm('Isso substituirá suas atividades atuais. Deseja continuar?')) {
                    return;
                }
            }

            // Example data from the article
            activities = [
                {
                    id: 1,
                    description: "Coleta de logs de autenticação do AD falhando há dias",
                    justification: "Sem logs do AD, não é possível detectar acessos suspeitos, brute force, lateral movement ou ataques como Pass-the-Hash e Kerberoasting.",
                    gravity: 5,
                    urgency: 4,
                    tendency: 5,
                    gut: 100
                },
                {
                    id: 2,
                    description: "Falha na coleta de logs de firewall",
                    justification: "Perda de visibilidade de entrada e saída da rede. Compromete a detecção de ataques externos e exfiltração de dados.",
                    gravity: 5,
                    urgency: 4,
                    tendency: 3,
                    gut: 60
                },
                {
                    id: 3,
                    description: "Corrigir parser de log",
                    justification: "Dados incorretos afetam correlação, dashboards e alertas. Impacta diretamente a detecção precisa de incidentes.",
                    gravity: 4,
                    urgency: 3,
                    tendency: 4,
                    gut: 48
                },
                {
                    id: 4,
                    description: "Criar novas regras de detecção",
                    justification: "Necessário para acompanhar novas ameaças e comportamentos de ataque que surgem constantemente.",
                    gravity: 4,
                    urgency: 3,
                    tendency: 4,
                    gut: 48
                },
                {
                    id: 5,
                    description: "Revisar regras de SIEM",
                    justification: "Garante que os alertas estejam atualizados, reduz falsos positivos e melhora a eficiência do SOC.",
                    gravity: 4,
                    urgency: 3,
                    tendency: 3,
                    gut: 36
                },
                {
                    id: 6,
                    description: "Mapear novas regras para tática MITRE",
                    justification: "Fortalece a cobertura por táticas e técnicas conhecidas. Evita lacunas de detecção.",
                    gravity: 4,
                    urgency: 3,
                    tendency: 3,
                    gut: 36
                },
                {
                    id: 7,
                    description: "Mapear ativos críticos",
                    justification: "Sem um inventário claro, é difícil priorizar alertas e proteger o que realmente importa.",
                    gravity: 5,
                    urgency: 2,
                    tendency: 3,
                    gut: 30
                },
                {
                    id: 8,
                    description: "Atualizar coletor de logs",
                    justification: "Coletores desatualizados podem falhar ou não suportar novos formatos de log.",
                    gravity: 3,
                    urgency: 3,
                    tendency: 3,
                    gut: 27
                },
                {
                    id: 9,
                    description: "Atualizar SIEM",
                    justification: "Versões antigas podem ter falhas de segurança, baixa performance ou falta de novos recursos.",
                    gravity: 4,
                    urgency: 2,
                    tendency: 3,
                    gut: 24
                },
                {
                    id: 10,
                    description: "Revisar regras Sigma",
                    justification: "As regras precisam acompanhar atualizações de ameaças e mudanças nos logs dos sistemas monitorados.",
                    gravity: 3,
                    urgency: 2,
                    tendency: 3,
                    gut: 18
                },
                {
                    id: 11,
                    description: "Desenvolver Playbook",
                    justification: "Padroniza e acelera a resposta a incidentes, reduzindo tempo de contenção e erro humano.",
                    gravity: 3,
                    urgency: 2,
                    tendency: 3,
                    gut: 18
                },
                {
                    id: 12,
                    description: "Relatório mensal",
                    justification: "Necessário para compliance e visibilidade da operação, mas sem impacto direto na detecção/resposta.",
                    gravity: 2,
                    urgency: 2,
                    tendency: 2,
                    gut: 8
                }
            ];
            
            saveToLocalStorage();
            renderActivities();
        }

        // Initialize the table on page load
        renderActivities();
