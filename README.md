##auto trigger##

project-root/
├─ orchestrator.ps1          # Main automation controller
├─ tasks.json                # Declarative list of tasks to execute
├─ scripts/
│  ├─ powershell/            # PowerShell scripts (.ps1)
│  ├─ cmd/                   # CMD/BAT scripts (.cmd/.bat)
│  └─ python/                # Python scripts (.py)
├─ bin/                      # External executables (.exe)
├─ logs/                     # Execution logs per run
└─ config/                   # Configuration files, inputs, etc.
