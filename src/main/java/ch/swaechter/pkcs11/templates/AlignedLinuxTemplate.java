package ch.swaechter.pkcs11.templates;

import java.lang.foreign.Arena;
import java.lang.foreign.GroupLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.ValueLayout.*;

/**
 * Template that represents a Linux system with 8 byte aligned struct layouts, mostly Linux x64. Long takes 8 bytes.
 *
 * @author Simon Wächter
 */
public class AlignedLinuxTemplate extends Template {

    /**
     * {@inheritDoc}
     */
    @Override
    public MemorySegment allocateLong(Arena arena) {
        return arena.allocate(JAVA_LONG);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MemorySegment allocateLong(Arena arena, long value) {
        return arena.allocate(JAVA_LONG, value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MemorySegment allocateLongArray(Arena arena, int size) {
        return arena.allocateArray(JAVA_LONG, size);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLong(MemorySegment memorySegment) {
        return memorySegment.get(JAVA_LONG, 0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLongFromArray(MemorySegment memorySegment, long index) {
        return memorySegment.get(JAVA_LONG, JAVA_LONG.byteSize() * index);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLong(MemorySegment memorySegment, GroupLayout groupLayout, String name) {
        VarHandle varHandle = groupLayout.varHandle(MemoryLayout.PathElement.groupElement(name));
        return (long) varHandle.get(memorySegment);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkVersionLayout() {
        return MemoryLayout.structLayout(
            JAVA_BYTE.withName("major"),
            JAVA_BYTE.withName("minor")
        );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkInfoLayout() {
        return MemoryLayout.structLayout(
            getCkVersionLayout().withName("cryptokiVersion"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("manufacturerId"),
            MemoryLayout.paddingLayout(6),
            JAVA_LONG.withName("flags"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("libraryDescription"),
            getCkVersionLayout().withName("libraryVersion"),
            MemoryLayout.paddingLayout(2)
        ).withName("CK_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkSlotInfoLayout() {
        return MemoryLayout.structLayout(
            MemoryLayout.sequenceLayout(64, JAVA_BYTE).withName("slotDescription"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("manufacturerId"),
            JAVA_LONG.withName("flags"),
            getCkVersionLayout().withName("hardwareVersion"),
            getCkVersionLayout().withName("firmwareVersion"),
            MemoryLayout.paddingLayout(4)
        ).withName("CK_SLOT_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkTokenInfoLayout() {
        return MemoryLayout.structLayout(
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("label"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("manufacturerId"),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("model"),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("serialNumber"),
            JAVA_LONG.withName("flags"),
            JAVA_LONG.withName("maxSessionCount"),
            JAVA_LONG.withName("sessionCount"),
            JAVA_LONG.withName("maxRwSessionCount"),
            JAVA_LONG.withName("rwSessionCount"),
            JAVA_LONG.withName("maxPinLen"),
            JAVA_LONG.withName("minPinLen"),
            JAVA_LONG.withName("totalPublicMemory"),
            JAVA_LONG.withName("freePublicMemory"),
            JAVA_LONG.withName("totalPrivateMemory"),
            JAVA_LONG.withName("freePrivateMemory"),
            getCkVersionLayout().withName("hardwareVersion"),
            getCkVersionLayout().withName("firmwareVersion"),
            MemoryLayout.paddingLayout(4),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("utcTime")
        ).withName("CK_TOKEN_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkSessionInfoLayout() {
        return MemoryLayout.structLayout(
            JAVA_LONG.withName("slotId"),
            JAVA_LONG.withName("state"),
            JAVA_LONG.withName("flags"),
            JAVA_LONG.withName("deviceError")
        ).withName("CK_SESSION_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkAttributeLayout() {
        return MemoryLayout.structLayout(
            JAVA_LONG.withName("type"),
            ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)).withName("pValue"),
            JAVA_LONG.withName("valueLen")
        ).withName("CK_ATTRIBUTE");
    }
}
