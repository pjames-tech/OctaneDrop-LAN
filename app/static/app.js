(function () {
  const input = document.getElementById('file-input');
  const dropzone = document.getElementById('dropzone');
  const selectedFiles = document.getElementById('selected-files');
  const clearSelectionButton = document.getElementById('clear-selection');
  const filesCard = document.querySelector('.files-card');
  const copyFeedback = document.getElementById('copy-feedback');
  const uploadForm = document.getElementById('upload-form');
  const uploadButton = uploadForm?.querySelector('button[type="submit"]');
  const liveStatus = document.getElementById('live-status');
  const liveDot = document.getElementById('live-dot');
  const toastStack = document.getElementById('toast-stack');

  let liveSignature = filesCard?.dataset.filesSignature || '';
  let uploadPending = false;
  let refreshQueued = false;
  let socket = null;
  let reconnectTimer = null;
  let reconnectAttempt = 0;
  let pingTimer = null;

  function showToast(message, kind = 'success', durationMs = 2600) {
    if (!toastStack || !message) {
      return;
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${kind}`;
    toast.role = 'status';
    toast.textContent = message;
    toastStack.appendChild(toast);

    // Trigger transition after insertion.
    window.requestAnimationFrame(() => {
      toast.classList.add('is-visible');
    });

    window.setTimeout(() => {
      toast.classList.remove('is-visible');
      toast.classList.add('is-leaving');
      window.setTimeout(() => toast.remove(), 260);
    }, durationMs);
  }

  function hydrateInitialToast() {
    if (!toastStack) {
      return;
    }
    const initialToast = toastStack.querySelector('.initial-toast');
    if (!initialToast) {
      return;
    }
    window.requestAnimationFrame(() => {
      initialToast.classList.add('is-visible');
    });
    window.setTimeout(() => {
      initialToast.classList.remove('is-visible');
      initialToast.classList.add('is-leaving');
      window.setTimeout(() => initialToast.remove(), 260);
    }, 2600);
  }

  function describeFiles(fileList) {
    if (!fileList || !fileList.length) {
      return 'No files selected.';
    }
    const names = Array.from(fileList).slice(0, 3).map(file => file.name);
    const remaining = fileList.length - names.length;
    return remaining > 0 ? `${names.join(', ')} + ${remaining} more` : names.join(', ');
  }

  function hasPendingLocalSelection() {
    return Boolean(input?.files?.length) && !uploadPending;
  }

  function updateSelectionUi() {
    if (selectedFiles) {
      selectedFiles.textContent = describeFiles(input?.files);
    }
    if (clearSelectionButton) {
      clearSelectionButton.classList.toggle('hidden', !input?.files?.length || uploadPending);
    }
  }

  function setLiveState(state, text) {
    if (liveStatus) {
      liveStatus.textContent = text;
    }
    if (liveDot) {
      liveDot.dataset.state = state;
    }
  }

  function reloadOrQueue(signature) {
    if (signature) {
      liveSignature = signature;
      filesCard.dataset.filesSignature = signature;
    }

    if (uploadPending || hasPendingLocalSelection()) {
      refreshQueued = true;
      setLiveState('waiting', 'Change detected. Refresh is waiting for your pending upload.');
      return;
    }

    window.location.reload();
  }

  function maybeRefreshQueued() {
    if (refreshQueued && !uploadPending && !hasPendingLocalSelection()) {
      window.location.reload();
    }
  }

  function clearReconnectTimer() {
    if (reconnectTimer) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  function clearPingTimer() {
    if (pingTimer) {
      window.clearInterval(pingTimer);
      pingTimer = null;
    }
  }

  function startPingTimer() {
    clearPingTimer();
    pingTimer = window.setInterval(() => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        try {
          socket.send('ping');
        } catch (_) {
          // Ignore transient socket issues.
        }
      }
    }, 25000);
  }

  function scheduleReconnect() {
    clearReconnectTimer();
    reconnectAttempt += 1;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempt - 1), 10000);
    setLiveState('connecting', 'Reconnecting live updates…');
    reconnectTimer = window.setTimeout(connectLiveUpdates, delay);
  }

  function connectLiveUpdates() {
    if (!filesCard || !('WebSocket' in window)) {
      return;
    }

    clearReconnectTimer();

    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${scheme}//${window.location.host}/ws/files`;

    try {
      socket = new WebSocket(wsUrl);
    } catch (_) {
      scheduleReconnect();
      return;
    }

    setLiveState('connecting', 'Connecting live updates…');

    socket.addEventListener('open', () => {
      reconnectAttempt = 0;
      startPingTimer();
      setLiveState('connected', 'Live updates connected');
    });

    socket.addEventListener('message', event => {
      try {
        const payload = JSON.parse(event.data);
        if (!payload || typeof payload !== 'object') {
          return;
        }

        if (payload.event === 'ready' && payload.signature) {
          liveSignature = payload.signature;
          filesCard.dataset.filesSignature = payload.signature;
          return;
        }

        if (payload.event === 'files_changed' && payload.signature && payload.signature !== liveSignature) {
          reloadOrQueue(payload.signature);
        }
      } catch (_) {
        // Ignore malformed frames.
      }
    });

    socket.addEventListener('close', () => {
      clearPingTimer();
      setLiveState('offline', 'Live updates disconnected');
      socket = null;
      scheduleReconnect();
    });

    socket.addEventListener('error', () => {
      clearPingTimer();
      setLiveState('offline', 'Live updates unavailable');
      socket?.close();
    });
  }

  if (input) {
    input.addEventListener('change', () => {
      updateSelectionUi();
      if (!input.files?.length) {
        maybeRefreshQueued();
      }
    });
    updateSelectionUi();
  }

  if (clearSelectionButton && input) {
    clearSelectionButton.addEventListener('click', () => {
      input.value = '';
      updateSelectionUi();
      maybeRefreshQueued();
    });
  }

  if (uploadForm) {
    uploadForm.addEventListener('submit', () => {
      uploadPending = true;
      if (selectedFiles) {
        selectedFiles.textContent = 'Uploading…';
      }
      if (clearSelectionButton) {
        clearSelectionButton.classList.add('hidden');
      }
      if (uploadButton) {
        uploadButton.disabled = true;
        uploadButton.textContent = 'Uploading…';
      }
    });
  }

  if (dropzone && input) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, event => {
        event.preventDefault();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, event => {
        event.preventDefault();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', event => {
      if (event.dataTransfer?.files?.length) {
        input.files = event.dataTransfer.files;
        updateSelectionUi();
      }
    });
  }

  async function copyToClipboard(text) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }

    const temp = document.createElement('textarea');
    temp.value = text;
    document.body.appendChild(temp);
    temp.select();
    document.execCommand('copy');
    temp.remove();
    return true;
  }

  async function handleShare(event) {
    const button = event.target.closest('.share-button');
    if (!button || !filesCard) {
      return;
    }

    const fileId = button.dataset.fileId;
    const csrfToken = filesCard.dataset.csrfToken;
    if (!fileId || !csrfToken) {
      return;
    }

    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = 'Creating…';

    try {
      const response = await fetch(`/api/files/${fileId}/share`, {
        method: 'POST',
        headers: {
          'X-CSRF-Token': csrfToken,
          'Accept': 'application/json'
        },
        credentials: 'same-origin'
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'Could not create share link.');
      }

      await copyToClipboard(payload.url);
      const successMessage = `Copied a ${Math.round(payload.expires_in_seconds / 60)} minute link for ${payload.filename}.`;
      if (copyFeedback) {
        copyFeedback.textContent = successMessage;
      }
      showToast(successMessage, 'success', 2200);
      button.textContent = 'Copied';
      window.setTimeout(() => {
        button.textContent = originalLabel;
        button.disabled = false;
      }, 1200);
      return;
    } catch (error) {
      const errorMessage = error.message || 'Could not copy the share link.';
      if (copyFeedback) {
        copyFeedback.textContent = errorMessage;
      }
      showToast(errorMessage, 'error', 3000);
      button.textContent = originalLabel;
      button.disabled = false;
    }
  }

  hydrateInitialToast();

  if (filesCard) {
    connectLiveUpdates();
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && (!socket || socket.readyState === WebSocket.CLOSED)) {
        connectLiveUpdates();
      }
      maybeRefreshQueued();
    });
    window.addEventListener('focus', () => {
      maybeRefreshQueued();
      if (!socket || socket.readyState === WebSocket.CLOSED) {
        connectLiveUpdates();
      }
    });
    window.addEventListener('beforeunload', () => {
      clearPingTimer();
      clearReconnectTimer();
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close(1000, 'Page unload');
      }
    });
    filesCard.addEventListener('click', handleShare);
  }

  document.querySelectorAll('.delete-form').forEach(form => {
    form.addEventListener('submit', event => {
      const fileName = form.dataset.fileName || 'this file';
      if (!window.confirm(`Delete ${fileName}?`)) {
        event.preventDefault();
      }
    });
  });

  document.querySelectorAll('.logout-confirm-form').forEach(form => {
    form.addEventListener('submit', event => {
      if (!window.confirm('Are you sure you want to log out?')) {
        event.preventDefault();
      }
    });
  });
})();
