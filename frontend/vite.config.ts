import path from "path"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    outDir: "../web/dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/screen.png': 'http://bjorn.local:8000',
      '/tool_log': 'http://bjorn.local:8000',
      '/load_config': 'http://bjorn.local:8000',
      '/save_config': 'http://bjorn.local:8000',
      '/scan_wifi': 'http://bjorn.local:8000',
      '/connect_wifi': 'http://bjorn.local:8000',
      '/disconnect_wifi': 'http://bjorn.local:8000',
      '/network_data': 'http://bjorn.local:8000',
      '/netkb_data': 'http://bjorn.local:8000',
      '/netkb_data_json': 'http://bjorn.local:8000',
      '/list_credentials': 'http://bjorn.local:8000',
      '/list_files': 'http://bjorn.local:8000',
      '/download_file': 'http://bjorn.local:8000',
      '/get_logs': 'http://bjorn.local:8000',
      '/get_web_delay': 'http://bjorn.local:8000',
      '/api': 'http://bjorn.local:8000',
      '/reboot': 'http://bjorn.local:8000',
      '/shutdown': 'http://bjorn.local:8000',
      '/restart_bjorn_service': 'http://bjorn.local:8000',
      '/clear_files': 'http://bjorn.local:8000',
      '/clear_files_light': 'http://bjorn.local:8000',
      '/initialize_csv': 'http://bjorn.local:8000',
      '/backup': 'http://bjorn.local:8000',
      '/restore': 'http://bjorn.local:8000',
      '/stop_orchestrator': 'http://bjorn.local:8000',
      '/start_orchestrator': 'http://bjorn.local:8000',
      '/execute_manual_attack': 'http://bjorn.local:8000',
      '/restore_default_config': 'http://bjorn.local:8000',
    },
  },
})
