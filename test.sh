CLUSTERSIZE=large
func() {
  case "$CLUSTERSIZE" in
  large)
    INDEXERCPU=1
    INDEXERMEMORY=2
    ;;
  small)
    INDEXERCPU=7
    INDEXERMEMORY=15
    ;;
  arbitrary)
    INDEXERCPU=7
    INDEXERMEMORY=15
    ;;

  esac
}
func
echo "$INDEXERCPU"
