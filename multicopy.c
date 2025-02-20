#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <ncurses.h>
#include <signal.h>

#define BUFFER_SIZE 65536 // 64 KB

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ------------------------------------------------------------------
 *                   VARIABILI GLOBALI
 * ------------------------------------------------------------------ */

// Lista dei file sorgente (percorsi relativi)
char **source_files = NULL;
int num_source_files = 0, source_files_capacity = 0;
pthread_mutex_t index_mutex = PTHREAD_MUTEX_INITIALIZER;
int next_index = 0;

// Directory globali (impostate dai parametri di esecuzione)
const char *g_src_dir;
const char *g_dest_dir;

// Variabili per la progress bar
int files_processed = 0;
pthread_mutex_t progress_mutex = PTHREAD_MUTEX_INITIALIZER;

// Finestre ncurses
static WINDOW *topWin = NULL;
static WINDOW *bottomWin = NULL;

// Mutex per la stampa (sia su topWin che bottomWin)
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------
 *                   FUNZIONI DI UTILITÀ
 * ------------------------------------------------------------------ */

// Funzione di pulizia di ncurses
static void cleanup_ncurses(void)
{
    if (topWin)
    {
        delwin(topWin);
        topWin = NULL;
    }
    if (bottomWin)
    {
        delwin(bottomWin);
        bottomWin = NULL;
    }
    endwin(); // Ripristina il terminale
}

// Signal handler per SIGINT, SIGTERM
static void signal_handler(int signum)
{
    cleanup_ncurses();
    _exit(signum);
}

// Concatena due percorsi: "dir" e "file". Se "file" è assoluto, lo duplica.
char *concat_path(const char *dir, const char *file)
{
    if (file[0] == '/')
    {
        return strdup(file);
    }
    size_t len_dir = strlen(dir);
    size_t len_file = strlen(file);
    char *path = malloc(len_dir + len_file + 2);
    if (!path)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    if (dir[len_dir - 1] == '/')
        sprintf(path, "%s%s", dir, file);
    else
        sprintf(path, "%s/%s", dir, file);
    return path;
}

// Calcola l'MD5 di un file leggendo a blocchi di BUFFER_SIZE.
int compute_md5(const char *filename, unsigned char *result)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        pthread_mutex_lock(&print_mutex);
        wprintw(topWin, "Errore apertura file per MD5: %s\n", filename);
        wrefresh(topWin);
        pthread_mutex_unlock(&print_mutex);
        return -1;
    }
    MD5_CTX mdContext;
    unsigned char data[BUFFER_SIZE];
    size_t bytes;
    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, BUFFER_SIZE, fp)) > 0)
    {
        MD5_Update(&mdContext, data, bytes);
    }
    MD5_Final(result, &mdContext);
    fclose(fp);
    return 0;
}

// Copia l'intero file da src a dest.
int copy_file(const char *src, const char *dest)
{
    FILE *in = fopen(src, "rb");
    if (!in)
    {
        pthread_mutex_lock(&print_mutex);
        wprintw(topWin, "Errore apertura file sorgente: %s\n", src);
        wrefresh(topWin);
        pthread_mutex_unlock(&print_mutex);
        return -1;
    }
    FILE *out = fopen(dest, "wb");
    if (!out)
    {
        pthread_mutex_lock(&print_mutex);
        wprintw(topWin, "Errore apertura file destinazione: %s\n", dest);
        wrefresh(topWin);
        pthread_mutex_unlock(&print_mutex);
        fclose(in);
        return -1;
    }
    char buffer[BUFFER_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, BUFFER_SIZE, in)) > 0)
    {
        if (fwrite(buffer, 1, bytes, out) != bytes)
        {
            pthread_mutex_lock(&print_mutex);
            wprintw(topWin, "Errore scrittura file destinazione: %s\n", dest);
            wrefresh(topWin);
            pthread_mutex_unlock(&print_mutex);
            fclose(in);
            fclose(out);
            return -1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

/* ------------------------------------------------------------------
 *                 DELTA COPY (block-by-block update)
 * ------------------------------------------------------------------ */
int delta_copy_file(const char *src, const char *dest)
{
    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Debug] Delta-copy inizio per: %s\n", src);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    struct stat stat_src, stat_dest;
    if (stat(src, &stat_src) != 0)
        return -1;
    if (stat(dest, &stat_dest) != 0)
        return copy_file(src, dest);
    if (stat_src.st_size != stat_dest.st_size)
        return copy_file(src, dest);

    FILE *f_src = fopen(src, "rb");
    FILE *f_dest = fopen(dest, "rb+");
    if (!f_src || !f_dest)
    {
        if (f_src)
            fclose(f_src);
        if (f_dest)
            fclose(f_dest);
        return copy_file(src, dest);
    }

    size_t bytes_read;
    long offset = 0;
    char src_buf[BUFFER_SIZE], dest_buf[BUFFER_SIZE];
    while ((bytes_read = fread(src_buf, 1, BUFFER_SIZE, f_src)) > 0)
    {
        size_t dest_bytes = fread(dest_buf, 1, BUFFER_SIZE, f_dest);
        if (dest_bytes != bytes_read || memcmp(src_buf, dest_buf, bytes_read) != 0)
        {
            fseek(f_dest, offset, SEEK_SET);
            if (fwrite(src_buf, 1, bytes_read, f_dest) != bytes_read)
            {
                fclose(f_src);
                fclose(f_dest);
                return -1;
            }
        }
        offset += bytes_read;
    }
    fclose(f_src);
    fclose(f_dest);

    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Debug] Delta-copy terminata per: %s\n", src);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    return 0;
}

/* ------------------------------------------------------------------
 *             CREAZIONE RICORSIVA DELLE DIRECTORY
 * ------------------------------------------------------------------ */
int mkdir_recursive(const char *dir, mode_t mode)
{
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST)
            {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
    {
        return -1;
    }
    return 0;
}

int ensure_directory_exists(const char *file_path)
{
    char *dup = strdup(file_path);
    if (!dup)
        return -1;
    char *last_slash = strrchr(dup, '/');
    if (last_slash)
    {
        *last_slash = '\0';
        if (mkdir_recursive(dup, 0755) != 0)
        {
            free(dup);
            return -1;
        }
    }
    free(dup);
    return 0;
}

/* ------------------------------------------------------------------
 *      SCANSIONE RICORSIVA DELLA CARTELLA SORGENTE
 * ------------------------------------------------------------------ */
void scan_source_recursive(const char *src_dir, const char *rel_path,
                           char ***file_list, int *file_count, int *capacity)
{
    char *current_path = (strlen(rel_path) == 0) ? strdup(src_dir)
                                                 : concat_path(src_dir, rel_path);

    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Debug] Scansione directory: %s\n", current_path);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    DIR *d = opendir(current_path);
    if (!d)
    {
        pthread_mutex_lock(&print_mutex);
        wprintw(topWin, "Errore apertura directory sorgente: %s\n", current_path);
        wrefresh(topWin);
        pthread_mutex_unlock(&print_mutex);
        free(current_path);
        return;
    }
    struct dirent *entry;
    struct stat statbuf;
    while ((entry = readdir(d)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char *new_rel = (strlen(rel_path) == 0) ? strdup(entry->d_name)
                                                : concat_path(rel_path, entry->d_name);
        char *entry_full = concat_path(src_dir, new_rel);
        if (stat(entry_full, &statbuf) == 0)
        {
            if (S_ISDIR(statbuf.st_mode))
            {
                pthread_mutex_lock(&print_mutex);
                wprintw(topWin, "[Debug] Trovata directory: %s\n", new_rel);
                wrefresh(topWin);
                pthread_mutex_unlock(&print_mutex);
                scan_source_recursive(src_dir, new_rel, file_list, file_count, capacity);
                free(new_rel);
            }
            else if (S_ISREG(statbuf.st_mode))
            {
                if (*file_count == *capacity)
                {
                    *capacity = (*capacity == 0) ? 10 : (*capacity * 2);
                    char **tmp_arr = realloc(*file_list, (*capacity) * sizeof(char *));
                    if (!tmp_arr)
                    {
                        pthread_mutex_lock(&print_mutex);
                        wprintw(topWin, "realloc file_list fallita.\n");
                        wrefresh(topWin);
                        pthread_mutex_unlock(&print_mutex);
                        exit(EXIT_FAILURE);
                    }
                    *file_list = tmp_arr;
                }
                (*file_list)[(*file_count)++] = new_rel;
                pthread_mutex_lock(&print_mutex);
                wprintw(topWin, "[Debug] File aggiunto: %s\n", new_rel);
                wrefresh(topWin);
                pthread_mutex_unlock(&print_mutex);
            }
            else
            {
                free(new_rel);
            }
        }
        else
        {
            free(new_rel);
        }
        free(entry_full);
    }
    closedir(d);
    free(current_path);
}

/* ------------------------------------------------------------------
 *       SALVA LA LISTA DEI FILE DA TRASFERIRE
 * ------------------------------------------------------------------ */
void save_source_file_list(const char *filename, char **file_list, int file_count)
{
    FILE *f = fopen(filename, "w");
    if (!f)
    {
        pthread_mutex_lock(&print_mutex);
        wprintw(topWin, "Errore apertura file lista: %s\n", filename);
        wrefresh(topWin);
        pthread_mutex_unlock(&print_mutex);
        return;
    }
    for (int i = 0; i < file_count; i++)
    {
        fprintf(f, "%s\n", file_list[i]);
    }
    fclose(f);
    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Debug] Lista dei file salvata in '%s' con %d file.\n",
            filename, file_count);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);
}

/* ------------------------------------------------------------------
 *             PROGRESS BAR NELLA FINESTRA bottomWin
 * ------------------------------------------------------------------ */
void *progress_thread(void *arg)
{
    (void)arg;
    int total = num_source_files;
    int bar_width = 50; // Larghezza della barra

    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Debug] Progress thread avviato.\n");
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    while (1)
    {
        pthread_mutex_lock(&progress_mutex);
        int done = files_processed;
        pthread_mutex_unlock(&progress_mutex);

        float percent = (total == 0) ? 100.0 : (100.0 * done / total);
        int pos = (int)(bar_width * percent / 100.0);

        pthread_mutex_lock(&print_mutex);
        werase(bottomWin);
        mvwprintw(bottomWin, 0, 0, "Progress: [");
        for (int i = 0; i < bar_width; i++)
        {
            waddch(bottomWin, (i < pos) ? '#' : ' ');
        }
        waddch(bottomWin, ']');
        wprintw(bottomWin, " %3.0f%% (%d/%d)", percent, done, total);
        wrefresh(bottomWin);

        // Aggiorna topWin se necessario
        wrefresh(topWin);
        pthread_mutex_unlock(&print_mutex);

        if (done >= total)
            break;
        sleep(1);
    }

    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Debug] Progress thread terminato.\n");
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    return NULL;
}

/* ------------------------------------------------------------------
 *             WORKER THREAD
 * ------------------------------------------------------------------ */
void *worker(void *arg)
{
    int thread_id = *((int *)arg);
    while (1)
    {
        pthread_mutex_lock(&index_mutex);
        if (next_index >= num_source_files)
        {
            pthread_mutex_unlock(&index_mutex);
            break;
        }
        int index = next_index++;
        pthread_mutex_unlock(&index_mutex);

        char *relative_filename = source_files[index];
        // Log
        pthread_mutex_lock(&print_mutex);
        wprintw(topWin, "[Thread %d] Elaboro file: %s\n", thread_id, relative_filename);
        wrefresh(topWin);
        pthread_mutex_unlock(&print_mutex);

        char *src_path = concat_path(g_src_dir, relative_filename);
        char *dest_path = concat_path(g_dest_dir, relative_filename);

        // Calcola MD5 del file sorgente
        unsigned char md5_src[MD5_DIGEST_LENGTH];
        if (compute_md5(src_path, md5_src) != 0)
        {
            pthread_mutex_lock(&print_mutex);
            wprintw(topWin, "[Thread %d] Errore calcolo MD5 per %s\n", thread_id, src_path);
            wrefresh(topWin);
            pthread_mutex_unlock(&print_mutex);
            free(src_path);
            free(dest_path);
            continue;
        }

        int need_copy = 0;
        struct stat st;
        if (stat(dest_path, &st) == 0)
        {
            // File esistente in destinazione
            unsigned char md5_dest[MD5_DIGEST_LENGTH];
            if (compute_md5(dest_path, md5_dest) != 0)
            {
                need_copy = 1;
                pthread_mutex_lock(&print_mutex);
                wprintw(topWin, "[Thread %d] Impossibile leggere file in dest, forzo copia: %s\n",
                        thread_id, relative_filename);
                wrefresh(topWin);
                pthread_mutex_unlock(&print_mutex);
            }
            else
            {
                // Confronto MD5
                if (memcmp(md5_src, md5_dest, MD5_DIGEST_LENGTH) != 0)
                {
                    need_copy = 1;
                    pthread_mutex_lock(&print_mutex);
                    wprintw(topWin, "[Thread %d] ~+ %s\n",
                            thread_id, relative_filename);
                    wrefresh(topWin);
                    pthread_mutex_unlock(&print_mutex);
                }
                else
                {
                    pthread_mutex_lock(&print_mutex);
                    wprintw(topWin, "[Thread %d] ~ %s\n", thread_id, relative_filename);
                    wrefresh(topWin);
                    pthread_mutex_unlock(&print_mutex);
                }
            }
        }
        else
        {
            // Nuovo file
            need_copy = 1;
            pthread_mutex_lock(&print_mutex);
            wprintw(topWin, "[Thread %d] + %s\n", thread_id, relative_filename);
            wrefresh(topWin);
            pthread_mutex_unlock(&print_mutex);
        }

        if (need_copy)
        {
            if (ensure_directory_exists(dest_path) != 0)
            {
                pthread_mutex_lock(&print_mutex);
                wprintw(topWin, "[Thread %d] Errore creazione directory per %s\n",
                        thread_id, dest_path);
                wrefresh(topWin);
                pthread_mutex_unlock(&print_mutex);
                free(src_path);
                free(dest_path);
                continue;
            }
            // Tenta la delta-copy
            if (stat(dest_path, &st) == 0)
            {
                if (delta_copy_file(src_path, dest_path) == 0)
                {
                    pthread_mutex_lock(&print_mutex);
                    wprintw(topWin, "[Thread %d] Δ~ %s\n",
                            thread_id, relative_filename);
                    wrefresh(topWin);
                    pthread_mutex_unlock(&print_mutex);
                }
                else
                {
                    pthread_mutex_lock(&print_mutex);
                    wprintw(topWin, "[Thread %d] Delta-copy fallita, copia completa: %s\n",
                            thread_id, relative_filename);
                    wrefresh(topWin);
                    pthread_mutex_unlock(&print_mutex);
                    copy_file(src_path, dest_path);
                }
            }
            else
            {
                copy_file(src_path, dest_path);
                pthread_mutex_lock(&print_mutex);
                wprintw(topWin, "[Thread %d] + %s\n",
                        thread_id, relative_filename);
                wrefresh(topWin);
                pthread_mutex_unlock(&print_mutex);
            }
        }

        free(src_path);
        free(dest_path);

        pthread_mutex_lock(&progress_mutex);
        files_processed++;
        pthread_mutex_unlock(&progress_mutex);
    }
    return NULL;
}

/* ------------------------------------------------------------------
 *             RIMOZIONE FILE EXTRA (git-clean like)
 * ------------------------------------------------------------------ */
int source_file_exists(const char *rel_path)
{
    for (int i = 0; i < num_source_files; i++)
    {
        if (strcmp(source_files[i], rel_path) == 0)
            return 1;
    }
    return 0;
}

void remove_extra_files(const char *dest_dir, const char *rel_path)
{
    char full_path[PATH_MAX];
    if (strlen(rel_path) == 0)
        snprintf(full_path, PATH_MAX, "%s", dest_dir);
    else
        snprintf(full_path, PATH_MAX, "%s/%s", dest_dir, rel_path);

    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Debug] Rimozione extra in: %s\n", full_path);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    DIR *d = opendir(full_path);
    if (!d)
        return;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char new_rel[PATH_MAX];
        if (strlen(rel_path) == 0)
            snprintf(new_rel, PATH_MAX, "%s", entry->d_name);
        else
            snprintf(new_rel, PATH_MAX, "%s/%s", rel_path, entry->d_name);

        char entry_full[PATH_MAX];
        snprintf(entry_full, PATH_MAX, "%s/%s", dest_dir, new_rel);
        struct stat st;
        if (stat(entry_full, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                remove_extra_files(dest_dir, new_rel);
                DIR *d2 = opendir(entry_full);
                if (d2)
                {
                    int empty = 1;
                    struct dirent *ent;
                    while ((ent = readdir(d2)) != NULL)
                    {
                        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                            continue;
                        empty = 0;
                        break;
                    }
                    closedir(d2);
                    if (empty)
                    {
                        if (rmdir(entry_full) == 0)
                        {
                            pthread_mutex_lock(&print_mutex);
                            wprintw(topWin, "[Main] Directory rimossa: %s\n", entry_full);
                            wrefresh(topWin);
                            pthread_mutex_unlock(&print_mutex);
                        }
                        else
                        {
                            pthread_mutex_lock(&print_mutex);
                            wprintw(topWin, "Errore rimozione directory: %s\n", entry_full);
                            wrefresh(topWin);
                            pthread_mutex_unlock(&print_mutex);
                        }
                    }
                }
            }
            else if (S_ISREG(st.st_mode))
            {
                if (!source_file_exists(new_rel))
                {
                    if (remove(entry_full) == 0)
                    {
                        pthread_mutex_lock(&print_mutex);
                        wprintw(topWin, "[Main] File rimosso: %s\n", entry_full);
                        wrefresh(topWin);
                        pthread_mutex_unlock(&print_mutex);
                    }
                    else
                    {
                        pthread_mutex_lock(&print_mutex);
                        wprintw(topWin, "Errore rimozione file: %s\n", entry_full);
                        wrefresh(topWin);
                        pthread_mutex_unlock(&print_mutex);
                    }
                }
            }
        }
    }
    closedir(d);
}

/* ------------------------------------------------------------------
 *             MAIN
 * ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Uso: %s <cartella_sorgente> <cartella_destinazione> [--threads=<num>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    g_src_dir = argv[1];
    g_dest_dir = argv[2];
    int num_threads = 1;
    if (argc >= 4)
    {
        if (strncmp(argv[3], "--threads=", 10) == 0)
        {
            num_threads = atoi(argv[3] + 10);
            if (num_threads <= 0)
            {
                fprintf(stderr, "Numero di thread non valido.\n");
                return EXIT_FAILURE;
            }
        }
    }

    // Installa i signal handler per gestire Ctrl+C (SIGINT), SIGTERM, ecc.
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Inizializza ncurses
    initscr();
    noecho();
    cbreak();

    // Creiamo la finestra topWin (in alto) e bottomWin (1 riga in fondo)
    int rows = LINES;
    int cols = COLS;
    topWin = newwin(rows - 1, cols, 0, 0);
    scrollok(topWin, TRUE); // i log possono scrollare
    bottomWin = newwin(1, cols, rows - 1, 0);
    scrollok(bottomWin, FALSE);

    // Messaggio iniziale
    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Main] Inizio scansione della cartella sorgente: %s\n", g_src_dir);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    // Scansione ricorsiva
    scan_source_recursive(g_src_dir, "", &source_files, &num_source_files, &source_files_capacity);

    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Main] Scansione completata. Totale file trovati: %d\n", num_source_files);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    // Salva la lista
    save_source_file_list("transfer_list.txt", source_files, num_source_files);

    // Avvio thread progress bar
    pthread_t progress_tid;
    if (pthread_create(&progress_tid, NULL, progress_thread, NULL) != 0)
    {
        // Se fallisce, puliamo e usciamo
        cleanup_ncurses();
        perror("pthread_create progress_thread");
        exit(EXIT_FAILURE);
    }

    // Avvio thread worker
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    int *thread_ids = malloc(num_threads * sizeof(int));
    if (!threads || !thread_ids)
    {
        cleanup_ncurses();
        perror("Allocazione thread");
        return EXIT_FAILURE;
    }

    pthread_mutex_lock(&print_mutex);
    wprintw(topWin, "[Main] Avvio trasferimento file con %d thread.\n", num_threads);
    wrefresh(topWin);
    pthread_mutex_unlock(&print_mutex);

    for (int i = 0; i < num_threads; i++)
    {
        thread_ids[i] = i + 1;
        if (pthread_create(&threads[i], NULL, worker, &thread_ids[i]) != 0)
        {
            pthread_mutex_lock(&print_mutex);
            wprintw(topWin, "pthread_create worker fallito.\n");
            wrefresh(topWin);
            pthread_mutex_unlock(&print_mutex);
        }
    }

    // Attendi i worker
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }
    free(threads);
    free(thread_ids);

    // Attendi progress bar
    pthread_join(progress_tid, NULL);

    // Ripristina ncurses
    cleanup_ncurses();

    // Rimozione dei file extra
    printf("[Main] Trasferimento completato. Inizio rimozione file/directory extra...\n");
    remove_extra_files(g_dest_dir, "");

    // Libera la lista
    for (int i = 0; i < num_source_files; i++)
    {
        free(source_files[i]);
    }
    free(source_files);

    printf("[Main] Operazione completata.\n");
    return EXIT_SUCCESS;
}
