document.addEventListener('DOMContentLoaded', function() {
    const flashMsgs = document.querySelectorAll('.flash');
    flashMsgs.forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = '0';
            msg.style.transition = 'opacity 0.4s';
            setTimeout(() => msg.remove(), 400);
        }, 4000);
    });

    const drops = document.querySelectorAll('.upload-zone');
    drops.forEach(zone => {
        zone.addEventListener('dragover', e => {
            e.preventDefault();
            zone.style.borderColor = 'var(--primary)';
            zone.style.background = 'var(--primary-light)';
        });
        zone.addEventListener('dragleave', () => {
            zone.style.borderColor = '';
            zone.style.background = '';
        });
        zone.addEventListener('drop', e => {
            e.preventDefault();
            zone.style.borderColor = '';
            zone.style.background = '';
            const input = zone.querySelector('input[type="file"]');
            if (input && e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                const label = zone.querySelector('#upload-text');
                if (label) label.textContent = e.dataTransfer.files[0].name;
            }
        });
    });
});
