{ inputs, system }:

let
  overlays = [ (import inputs.rust-overlay) ];
  pkgs = import inputs.nixpkgs { inherit system overlays; };
  lang_helpers = {
    rust = {
      toolchain = pkgs.rust-bin.stable."1.89.0".default.override { # choose version, ex : "latest"
        extensions = [
          "rust-analyzer"
          "rust-src"
        ];
        targets = [
          # Main platforms, check "rustc --print target-list" for more !
          "x86_64-unknown-linux-gnu"
          # "x86_64-unknown-linux-musl"
        ];
      };
    };
  };
  nvim = inputs.nixvim.legacyPackages.${system}.makeNixvim {
    globals.mapleader = " ";
    colorschemes.catppuccin.enable = true;
    opts = {
      number = true;
      # Use Tab as spaces
      shiftwidth = 2;
      tabstop = 2;
      expandtab = true;
      # Folding
      foldenable = true;
      foldcolumn = "1";
      foldlevel = 99;
      foldlevelstart = 99;
      foldmethod = "expr";
      foldexpr = "v:lua.vim.treesitter.foldexpr()";
    };
    plugins = {
      # Miscellaneous
      telescope.enable = true;
      nvim-ufo.enable = true;
      overseer.enable = true;
      treesitter = {
        enable = true;
        settings = {
          highlight.enable = true;
        };
      };
      gitblame.enable = true;

      # UI
      nvim-tree = {
        enable = true;
        openOnSetup = true;
        openOnSetupFile = false;
        settings = {
          diagnostics.enable = true;
          modified.enable = true;
        };
      };
      bufferline.enable = true;
      lualine.enable = true;
      which-key.enable = true;
      web-devicons.enable = true;
      smear-cursor = {
        enable = true;
        settings = {
          stiffness = 0.8;
          trailing_stiffness = 0.6;
          stiffness_insert_mode = 0.7;
          trailing_stiffness_insert_mode = 0.7;
          damping = 0.95;
          damping_insert_mode = 0.95;
          distance_stop_animating = 0.5;
        };
      };
      neoscroll = {
        enable = true;
        settings = {
          duration_multiplier = 0.5;
        };
      };
      mini = {
        # Note that some hackery is also made on VimEnter event
        enable = true;
        modules = {
          indentscope = { };
          cursorword = { };
          map = { };
          diff = { };
        };
      };
      scrollview = {
        enable = true;
        settings = {
          signs_on_startup = [ "all" ];
          excluded_filetypes = [ "dashboard" "NvimTree" "TelescopePrompt" ];
          winblend = 50;
        };
      };
      opencode = {
        enable = true;
        # settings.pro
      };
      snacks = { # required by opencode
        enable = true;
        settings = {
          input.enabled = true;
          picker.enabled = true;
          terminal.enabled = true;
        };
      };

      # Completion
      cmp = {
        enable = true;
        autoEnableSources = true;
        settings = {
          experimental = {
            ghost_text = true;
          };
          mapping = {
            __raw = ''
              cmp.mapping.preset.insert({
                ['<CR>'] = cmp.mapping.confirm({ select = true }),
                ['<Tab>'] = cmp.mapping.select_next_item(),
                ['<S-Tab>'] = cmp.mapping.select_prev_item(),
                ['<Esc>'] = cmp.mapping.abort(),
              })
            '';
          };
          sources = [
            { name = "nvim_lsp"; }
            { name = "luasnip"; }
            { name = "treesitter"; }
            { name = "path"; }
            { name = "buffer"; }
          ];
        };
      };

      # Snippets
      luasnip = {
        enable = true;
        settings = {
          enable_autosnippets = true;
        };
      };
      friendly-snippets.enable = true;

      # Debugger
      dap.enable = true;
      dap-ui.enable = true;
      dap-virtual-text.enable = true;
      ## language adapters
      ## DAP Configuration
      dap-lldb = {
        enable = true;
        settings = {
          codelldb_path = "${pkgs.vscode-extensions.vadimcn.vscode-lldb.out}/share/vscode/extensions/vadimcn.vscode-lldb/adapter/codelldb";
          configurations = {
            rust = [
              {
                name = "Debug: rust";
                type = "lldb";
                request = "launch";
                program = "\${workspaceFolder}/target/debug/coruscant";
                cwd = "\${workspaceFolder}";
              }
              {
                name = "Debug: rust (+ hardcoded args)";
                type = "lldb";
                request = "launch";
                program = "\${workspaceFolder}/target/debug/coruscant";
                args = ["sha1" "/etc/shadow"];
                cwd = "\${workspaceFolder}";
              }
            ];
          };
        };
      };

      # LSP
      # lspconfig.enable = true; # replaced by the lsp.enable module directly
      lsp = {
        enable = true;
        inlayHints = true;
      };
      lsp-lines.enable = true;
      lsp-format.enable = true;
      lsp-signature.enable = true;

      # Diagnostic
      trouble.enable = true;
    };
    lsp.servers = {
      jsonls.enable = true;   # json
      yamlls.enable = true;   # yaml
      nixd.enable = true;     # nix
      rust_analyzer.enable = true; # rust
    };
    extraPlugins = [
      (pkgs.vimUtils.buildVimPlugin {
        name = "fast-cursor-move";
        src = pkgs.fetchFromGitHub {
          owner = "xiyaowong";
          repo = "fast-cursor-move.nvim";
          rev = "9ab80d0184861be18833647e983086725b9905f9";
          hash = "sha256-Il9xPvSoREWqJ3vBT90aJVEYoRkoyOX5FezKKUrVND0=";
        };
        postPatch = ''
          substituteInPlace plugin/fast-cursor-move.lua \
            --replace \
            "local ACCELERATION_TABLE_VERTICAL = { 7, 14, 20, 26, 31, 36, 40 }" \
            "local ACCELERATION_TABLE_VERTICAL = { 2, 3 }"
          substituteInPlace plugin/fast-cursor-move.lua \
            --replace \
            "local ACCELERATION_TABLE_HORIZONTAL = { 10, 15, 20 }" \
            "local ACCELERATION_TABLE_HORIZONTAL = { 2, 3 }" \
        '';
      })
      # # Because of the following bug
      # # https://github.com/NickvanDyke/opencode.nvim/issues/83
      # # TODO :  When the issues is closed, replace this code with the nixvim module
      # (pkgs.vimUtils.buildVimPlugin {
      #   name = "opencode";
      #   src = pkgs.fetchFromGitHub {
      #     owner = "NickvanDyke";
      #     repo = "opencode.nvim";
      #     rev = "5e1ee1c7e1ee4b618e2411c61b30cba332975a35";
      #     hash = "sha256-UOB4qo7nqO/PLvSgSY3+3Mqno/jj/fnEw32gQrLNIgM=";
      #   };
      # })
      inputs.rustowl-flake.packages.${system}.rustowl-nvim
    ];

    extraConfigLuaPost = ''
      require('rustowl').setup({
        auto_attach = true,
        auto_enable = true,
        idle_time = 500,
        client = {},
        highlight_style = 'undercurl',
      })
    '';

    extraPackages = [
      inputs.rustowl-flake.packages.${system}.rustowl
    ];

    keymaps = [
      # Miscellaneous keymaps
      {
        key = "<Tab><Tab>";
        action = "<cmd>:b#<CR>";
        options.desc = "Switch to last buffer";
      }
      {
        key = "<Tab><Right>";
        action = "<cmd>BufferLineCycleNext<CR>";
      }
      {
        key = "<Tab><Left>";
        action = "<cmd>BufferLineCyclePrev<CR>";
      }
      {
        key = "<Tab>l";
        action = "<cmd>BufferLineCycleNext<CR>";
      }
      {
        key = "<Tab>h";
        action = "<cmd>BufferLineCyclePrev<CR>";
      }
      {
        key = "<C-q>";
        action = "<cmd>:qa!<CR>";
        options.desc = "Close/Abort neovim instance";
      }
      {
        key = "<C-x>";
        action = "<cmd>bd<CR><cmd>bNext<CR>";
        options.desc = "Close current buffer and focus on the next one";
      }
      {
        key = "<leader>e";
        action = "<cmd>NvimTreeToggle<CR>";
      }
      {
        key = "<leader>ft";
        action = "<cmd>Telescope<CR>";
      }
      {
        key = "<leader>fb";
        action = "<cmd>Telescope buffers<CR>";
      }
      {
        key = "<leader>fc";
        action = "<cmd>Telescope commands<CR>";
      }
      {
        key = "<leader>ff";
        action = "<cmd>Telescope find_files<CR>";
      }
      {
        key = "<leader>fg";
        action = "<cmd>Telescope live_grep<CR>";
      }
      {
        key = "<leader>tr";
        action = "<cmd>Trouble diagnostics<CR>";
      }
      # Buildsystem keymaps
      {
        key = "<F1>";
        action = "<cmd>CMakeGenerate<CR>";
        options.desc = "CMake Generate";
      }
      {
        key = "<F2>";
        action = "<cmd>CMakeBuild<CR>";
        options.desc = "CMake Build";
      }
      {
        key = "<F3>";
        action = "<cmd>CMakeRun<CR>";
        options.desc = "CMake Run";
      }
      # LSP
      {
        key = "<leader>lr";
        action = "<cmd>lua vim.lsp.buf.references()<CR>";
        options.desc = "Find references";
      }
      {
        key = "<leader>lD";
        action = "<cmd>lua vim.lsp.buf.declaration()<CR>";
        options.desc = "Find declaration";
      }
      {
        key = "<leader>ld";
        action = "<cmd>lua vim.lsp.buf.definition()<CR>";
        options.desc = "Find definition";
      }
      {
        key = "<leader>la";
        action = "<cmd>lua vim.lsp.buf.code_action()<CR>";
        options.desc = "Quickfix";
      }
      {
        key = "<leader>lh";
        action.__raw = "function() vim.lsp.inlay_hint.enable(not vim.lsp.inlay_hint.is_enabled()) end";
        options.desc = "Toggle inlay hints";
      }
      {
        key = "<leader>te";
        mode = [ "n" ];
        options.desc = "Terminal (bottom)";
        action.__raw = ''
          function()
            require('snacks.terminal').toggle('zsh', { win = { position = 'bottom' } })
          end
        '';
      }
      # AI
      {
        key = "<leader>oc";
        # key = "<C-.>";
        mode = [ "n" "t" ];
        options.desc = "Toggle OpenCode";
        action.__raw = ''
          function()
            require('snacks.terminal').toggle('opencode --port', { win = { position = 'right', enter = false } })
          end
        '';
      }
      {
        key = "<leader>oa";
        options.desc = "Ask opencode about selection";
        mode = "v";
        action.__raw = "function() require('opencode').ask('@this: ') end";
      }
      {
        key = "<leader>os";
        options.desc = "Select opencode prompt";
        mode = ["n" "v"];
        action.__raw = "function() require('opencode').select() end";
      }
      # RustOwl
      {
        key = "<leader>tr";
        action = "<cmd>Rustowl toggle<CR>";
        options.desc = "Toggle RustOwl";
      }
      # Overseer
      {
        key = "<leader>ot";
        action = "<cmd>OverseerToggle<CR>";
        options.desc = "Overseer Toggle";
      }
      {
        key = "<leader>or";
        action = "<cmd>OverseerRun<CR>";
        options.desc = "Overseer Run";
      }
      # Debugging keymaps
      {
        key = "<leader>d";
        action = "<cmd>lua require('dapui').toggle()<CR>";
        options.desc = "Toggle debug interface";
      }
      {
        key = "<leader>b";
        action = "<cmd>DapToggleBreakpoint<CR>";
        options.desc = "Toggle Breakpoint";
      }
      {
        key = "<F5>";
        action = "<cmd>DapContinue<CR>";
        options.desc = "Run/Continue";
      }
      {
        key = "<F6>";
        action = "<cmd>DapStepInto<CR>";
        options.desc = "Step Into";
      }
      {
        key = "<F7>";
        action = "<cmd>DapStepOver<CR>";
        options.desc = "Step Over";
      }
      {
        key = "<F8>";
        action = "<cmd>DapStepOut<CR>";
        options.desc = "Step Out";
      }
      {
        key = "<F9>";
        action = "<cmd>DapTerminate<CR>";
        options.desc = "Terminate";
      }
    ];

    userCommands = {
      ToggleCursorAcceleration = {
        command = ''
          lua vim.g.fast_cursor_move_acceleration = not vim.g.fast_cursor_move_acceleration
        '';
      };
      ToggleLspLines = {
        command = ''
          lua require('lsp_lines').toggle()
        '';
      };
      ToggleInlayHint = {
        command = ''
          lua vim.lsp.inlay_hint.enable(not vim.lsp.inlay_hint.is_enabled())
        '';
      };
      ToggleMinimap = {
        command = ''
          lua MiniMap.toggle()
        '';
      };
      ToggleFoldColumn = {
        command = ''
          lua vim.o.foldcolumn = (vim.o.foldcolumn == "0") and "1" or "0"
        '';
      };
      BufferRefresh = {
        command = ''
          :e!
        '';
      };
    };

    autoCmd = [
      {
        event = [ "VimEnter" ];
        desc = "On start focus on right window, automatically display dashboard if no buffer";
        callback.__raw = ''
          function()
            vim.cmd("wincmd l")
          end
        '';
      }
      {
        event = [ "VimEnter" ];
        desc = "Setup MiniDiff with git+save sources";
        callback.__raw = ''
          function()
            MiniDiff.setup({ source = { MiniDiff.gen_source.git(), MiniDiff.gen_source.save() }})
          end
        '';
      }
      {
        event = [ "TermOpen" ];
        desc = "Terminal window navigation keymaps";
        callback.__raw = ''
          function()
            local opts = { buffer = 0 }
            vim.keymap.set('t', '<C-p>', [[<Cmd>wincmd p<CR>]], opts)
            vim.keymap.set('t', '<C-h>', [[<Cmd>wincmd h<CR>]], opts)
            vim.keymap.set('t', '<C-j>', [[<Cmd>wincmd j<CR>]], opts)
            vim.keymap.set('t', '<C-k>', [[<Cmd>wincmd k<CR>]], opts)
            vim.keymap.set('t', '<C-l>', [[<Cmd>wincmd l<CR>]], opts)
            vim.keymap.set('t', '<C-w>', [[<C-\><C-n><C-w>]], opts)
          end
        '';
      }
      { event = [ "VimEnter" ]; command = "ToggleCursorAcceleration"; }
      { event = [ "VimEnter" ]; command = "ToggleLspLines"; }
    ];

  };
in
pkgs.mkShellNoCC {
  packages = [
    nvim
    lang_helpers.rust.toolchain

    ## RustOWL LSP server (needs cargo in PATH)
    # inputs.rustowl-flake.packages.${system}.rustowl

    ## Misc
    pkgs.bintools # Helpers and utilities, includes : ld, strip, strings, objdump, nm, etc...

    # Utils
    pkgs.zsh
    pkgs.ripgrep # for nvim livegrep
    # pkgs.opencode
    # pkgs.lsof # used by opencode

    # OSXCross dependencies
    # pkgs.rcodesign pkgs.darwin.libiconv
    # # python
    # pkgs.libxml2
    # pkgs.openssl
    # pkgs.xz
    # pkgs.zlib
    # # Added by yunor on 31/12/2025 just for debug purpose, to remove !
    # pkgs.libgcc

    # Other dependencies:
    # pkgs.openssl
    # pkgs.pkg-config
  ];

  shellHook = ''
    # # Set up rustowl sysroot symlink so it finds its nightly toolchain at runtime.
    # # Rustowl looks for ~/.rustowl/sysroot/<version>-<toolchain>/ where the version
    # # format is like "1.94.0-nightly-2026-01-16" (baked into the binary at build time).
    # RUSTOWL_NIGHTLY_PATH="$(${inputs.rustowl-flake.packages.${system}.rustowl}/bin/rustowlc --print sysroot 2>/dev/null)"
    # RUSTOWL_TOOLCHAIN_NAME="$(${inputs.rustowl-flake.packages.${system}.rustowl}/bin/rustowl --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+-nightly-\d{4}-\d{2}-\d{2}' | head -1)"
    # if [ -n "$RUSTOWL_NIGHTLY_PATH" ] && [ -n "$RUSTOWL_TOOLCHAIN_NAME" ] && [ -d "$RUSTOWL_NIGHTLY_PATH" ]; then
    #   mkdir -p "$HOME/.rustowl/sysroot"
    #   if [ "$(readlink -f "$HOME/.rustowl/sysroot/$RUSTOWL_TOOLCHAIN_NAME" 2>/dev/null)" != "$RUSTOWL_NIGHTLY_PATH" ]; then
    #     ln -sfn "$RUSTOWL_NIGHTLY_PATH" "$HOME/.rustowl/sysroot/$RUSTOWL_TOOLCHAIN_NAME"
    #   fi
    # fi
  '';
}
